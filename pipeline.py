from pathlib import Path
from pipeline_state import (documentation_dir, is_managed_documentation, collection_paths, collection_walk,
                            collection_directory, load_status, create_status)
import hashlib
from datetime import datetime
from lxml import etree as LET
import uuid
import logging
import csv
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
import shutil
import os
import mimetypes
import tarfile
import subprocess
import re
import json
import time
import tempfile
import stat
import signal
from copy import deepcopy

# ==========================
# DOCUMENTATION DESTINATIONS
# ==========================

def new_document(output, filename, accession_number):
    """Reserve a fresh name without replacing existing reports or logs."""
    destination = documentation_dir(output, accession_number) / filename
    while True:
        try:
            with destination.open("x", encoding="utf-8"):
                pass
            return destination
        except FileExistsError:
            name = Path(filename)
            destination = destination.parent / f"{name.stem}_{uuid.uuid4().hex}{name.suffix}"


# ==========================
# OPTIONAL DEPENDENCIES
# ==========================

try:
    import bagit
    BAGIT_AVAILABLE = True
except ImportError:
    BAGIT_AVAILABLE = False

# APTrust constants — exported so the GUI can import them
APTRUST_PROFILE_IDENTIFIER = (
    "https://raw.githubusercontent.com/APTrust/preservation-services"
    "/master/profiles/aptrust-v2.2.json"
)
APTRUST_ACCESS_VALUES   = ["Institution", "Restricted", "Consortia"]
APTRUST_STORAGE_OPTIONS = [
    "Standard",
    "Glacier-OH", "Glacier-OR", "Glacier-VA",
    "Glacier-Deep-OH", "Glacier-Deep-OR", "Glacier-Deep-VA",
]


# ==========================
# MICROSOFT DEFENDER DISCOVERY
# ==========================

def find_defender_executable():
    """Find the newest installed Defender platform, then standard fallbacks."""
    if os.name != "nt":
        return None

    platform = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    try:
        candidates = sorted(
            platform.glob("*/MpCmdRun.exe"),
            key=lambda p: tuple(int(n) for n in re.findall(r"\d+", p.parent.name)),
            reverse=True,
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    except OSError:
        logging.exception("Could not inspect Microsoft Defender platform directory.")

    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
    try:
        if fallback.is_file():
            return fallback
        executable = shutil.which("MpCmdRun.exe")
        if executable:
            return Path(executable)
    except OSError:
        logging.exception("Could not inspect Microsoft Defender fallback locations.")
    return None


def is_defender_operational():
    """Check Defender status without scanning or changing security settings."""
    if os.name != "nt" or DEFENDER_PATH is None:
        return False
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference = 'Stop'; Get-MpComputerStatus | "
                "Select-Object AMServiceEnabled, AntivirusEnabled, AMRunningMode | "
                "ConvertTo-Json -Compress",
            ],
            shell=False, capture_output=True, text=True, errors="replace",
            timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            logging.warning("Could not query Microsoft Defender status: %s", result.stderr.strip())
            return False
        status = json.loads(result.stdout)
        if not isinstance(status, dict):
            return False
        mode = status.get("AMRunningMode")
        return (
            status.get("AMServiceEnabled") is True
            and status.get("AntivirusEnabled") is True
            and isinstance(mode, str)
            and bool(mode.strip())
            and mode.strip().casefold() != "not running"
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        logging.warning("Could not query Microsoft Defender status.", exc_info=True)
        return False


DEFENDER_PATH = find_defender_executable()
AV_AVAILABLE = is_defender_operational()


# ==========================
# CHUNKED MD5
# ==========================

def compute_md5(file_path, chunk_size=1024 * 1024):
    """Compute MD5 checksum using chunked reading (1 MB default chunk)."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
    return md5.hexdigest()


def compute_sha256(file_path, chunk_size=1024 * 1024):
    """Compute a preservation digest with bounded memory."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with open(file_path, "rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def stored_checksum(record):
    """Read an explicitly identified baseline; never reinterpret legacy MD5."""
    values = {}
    for attribute, algorithm, length in (("SHA256", "SHA-256", 64), ("MD5", "MD5", 32)):
        if attribute in record.attrib:
            value = record.get(attribute, "")
            if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value):
                raise ValueError(f"Invalid {algorithm} baseline for {record.get('name')}")
            values[algorithm] = value.lower()
    for fixity in record.findall(f"{{{PREMIS_NS}}}object/{{{PREMIS_NS}}}objectCharacteristics/{{{PREMIS_NS}}}fixity"):
        algorithm = fixity.findtext(f"{{{PREMIS_NS}}}messageDigestAlgorithm", "")
        algorithm = {"SHA256": "SHA-256", "SHA-256": "SHA-256", "MD5": "MD5"}.get(algorithm.upper())
        if algorithm is None:
            raise ValueError("Unsupported PREMIS checksum algorithm")
        value = fixity.findtext(f"{{{PREMIS_NS}}}messageDigest", "").lower()
        length = 64 if algorithm == "SHA-256" else 32
        if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value) or (algorithm in values and values[algorithm] != value):
            raise ValueError("Invalid or conflicting PREMIS checksum")
        values[algorithm] = value
    for algorithm in ("SHA-256", "MD5"):
        if algorithm in values:
            return algorithm, values[algorithm]
    raise ValueError("Missing supported checksum baseline")


def compute_checksum(path, algorithm):
    return compute_sha256(path) if algorithm == "SHA-256" else compute_md5(path)


# ==========================
# ANTIVIRUS SCANNER
# ==========================

def run_antivirus_scan(data_directory, output_folder, accession_number, result_callback=None):
    """Scan sequentially with Defender, returning transferable paths, detections,
    and whether antivirus verification was unavailable. Only detections are
    excluded; scan errors and cloud placeholders remain transferable.
    Optional result_callback receives this attempt's counts/outcome and only
    successfully written report paths; the existing return tuple is unchanged.
    """
    data_directory = Path(data_directory).resolve()
    output_folder = Path(output_folder)
    all_files = {p for p in collection_paths(data_directory) if p.is_file()}
    defender_path = DEFENDER_PATH
    if not AV_AVAILABLE or defender_path is None:
        if defender_path is None:
            logging.warning("Microsoft Defender MpCmdRun.exe was not found. Antivirus scan skipped.")
        else:
            logging.warning(
                "Microsoft Defender executable was found, but Defender Antivirus is not operational. "
                "Antivirus scan skipped."
            )
        if result_callback is not None:
            result_callback(dict(state="failed", outcome="unavailable", scanned_count=0,
                                 detection_count=0, error_count=None, outputs={}))
        return set(all_files), {}, True

    logging.info("Microsoft Defender executable: %s", defender_path)
    logging.info("Scanning %s files with Microsoft Defender...", len(all_files))
    cloud_extensions = {".gdoc", ".gsheet", ".gslides", ".gdraw", ".gform", ".gmap", ".gsite"}
    cloud_message = "Google-native file must be exported/downloaded before content can be antivirus scanned."
    infected_files = {}
    results = []
    file_logs = []
    scanned = 0
    service_unavailable = 0

    for file_path in sorted(all_files):
        status, threat, return_code = "SCAN_ERROR", "", ""
        raw_output = None
        if file_path.suffix.lower() in cloud_extensions:
            status, threat = "SKIPPED_CLOUD_NATIVE", cloud_message
        else:
            try:
                if not file_path.is_file():
                    raise FileNotFoundError(f"File disappeared before scan: {file_path}")
                command = [
                    str(defender_path), "-Scan", "-ScanType", "3",
                    "-File", str(file_path.resolve()), "-DisableRemediation",
                ]
                completed = subprocess.run(
                    command, shell=False, capture_output=True, text=True,
                    errors="replace",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                scanned += 1
                return_code = completed.returncode
                raw_output = (completed.stdout or "") + "\n" + (completed.stderr or "")
                counts = [0 if n.lower() == "no" else int(n) for n in re.findall(
                    r"\b(?:found|MpScan\(\)\s+has\s+detected)\s+(\d+|no)\s+threats?\b",
                    raw_output, re.IGNORECASE,
                )]
                # Positive evidence takes precedence over any zero-count line.
                if any(count > 0 for count in counts):
                    status = "FLAGGED"
                    names = re.findall(
                        r"^\s*(?:threat(?:\s+name)?|signature(?:\s+name)?)\s*[:=]\s*(\S[^\r\n]*)",
                        raw_output, re.IGNORECASE | re.MULTILINE,
                    )
                    threat = "; ".join(dict.fromkeys(name.strip() for name in names)) or "Microsoft Defender detection"
                    infected_files[file_path] = threat
                elif counts and return_code == 0:
                    status = "CLEAN"
                else:
                    threat = "Microsoft Defender scan failed or output did not confirm a threat count."
                    if re.search(
                        r"0x800106ba|0x80070422|(?:service|Defender)[^\r\n]*(?:unavailable|disabled|not running)",
                        raw_output, re.IGNORECASE,
                    ):
                        service_unavailable += 1
            except (OSError, subprocess.SubprocessError) as exc:
                threat = str(exc)
                logging.exception("Microsoft Defender scan could not run for %s", file_path)

        results.append({
            "file_path": str(file_path), "status": status,
            "threat": threat, "return_code": return_code,
        })
        log_result = f"[{status}] {file_path}\n"
        if threat:
            log_result += f"{threat}\n"
        if raw_output is not None:
            log_result += f"Return code: {return_code}\n--- Defender output ---\n{raw_output}\n--- End Defender output ---\n"
        file_logs.append(log_result)
        log = logging.error if status == "SCAN_ERROR" else logging.warning if status == "FLAGGED" else logging.info
        log("[AV:%s] %s %s", status, file_path, threat)

    counts = Counter(result["status"] for result in results)
    header = (
        f"--- Microsoft Defender Scan: {datetime.now().isoformat()} ---\n"
        f"Defender executable: {defender_path}\nScan root: {data_directory}\n"
        f"Files discovered: {len(all_files)}\nFiles scanned: {scanned}\n"
        f"Files flagged: {len(infected_files)}\nScan errors: {counts['SCAN_ERROR']}\n"
        f"Google-native placeholders skipped: {counts['SKIPPED_CLOUD_NATIVE']}\n\n"
    )
    av_csv_file = new_document(output_folder, f"antivirus_{accession_number}.csv", accession_number)
    av_log_file = new_document(output_folder, f"antivirus_{accession_number}.log", accession_number)
    written_outputs = {}
    try:
        output_folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        logging.exception("Could not create antivirus report directory: %s", output_folder)
    try:
        with open(av_csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["file_path", "status", "threat", "return_code"])
            writer.writeheader()
            writer.writerows(results)
        written_outputs["csv"] = av_csv_file
    except OSError:
        logging.exception("Could not write Microsoft Defender CSV: %s", av_csv_file)
    try:
        av_log_file.write_text(header + "\n".join(file_logs), encoding="utf-8")
        written_outputs["log"] = av_log_file
    except OSError:
        logging.exception("Could not write Microsoft Defender log: %s", av_log_file)
        # Preserve the scan evidence in the pipeline log if the AV log fails.
        logging.error("%s%s", header, "\n".join(file_logs))

    clean_files = all_files - set(infected_files.keys())
    scan_candidates = len(all_files) - counts["SKIPPED_CLOUD_NATIVE"]
    av_skipped = scan_candidates > 0 and (scanned == 0 or service_unavailable == scanned)
    if av_skipped:
        logging.warning("Microsoft Defender verification unavailable. Pipeline will continue without antivirus scanning.")
    if result_callback is not None:
        outcome = ("unavailable" if av_skipped else "empty" if not all_files else
                   "detections" if infected_files else "partial" if
                   counts["SCAN_ERROR"] or counts["SKIPPED_CLOUD_NATIVE"] else "clean")
        result_callback(dict(state="failed" if av_skipped else "completed", outcome=outcome,
                             scanned_count=scanned, detection_count=len(infected_files),
                             error_count=counts["SCAN_ERROR"],
                             skipped_count=counts["SKIPPED_CLOUD_NATIVE"], outputs=written_outputs))
    return clean_files, infected_files, av_skipped


# ==========================
# DATA ACCESSIONER
# ==========================

PREMIS_NS = "info:lc/xmlns/premis-v2"
FITS_NS = "http://hul.harvard.edu/ois/xml/ns/fits/fits_output"
XSLT_DIR = Path(__file__).resolve().parent / "resources" / "xslt"
FITS_PROFILE = Path(__file__).resolve().parent / "fits" / "config" / "fits-droid.xml"


def configure_fits(fits_home=None):
    """Validate once per accession. Return (home, java), or None to skip FITS."""
    def unavailable(code, detail):
        logging.warning("[FITS:%s] %s Format identification skipped for this accession; "
                        "transfer, UUID, SHA-256 and size continue. See install/setup.md for setup.", code, detail)

    launcher_name = "fits.bat" if os.name == "nt" else "fits.sh"
    configured = fits_home or os.environ.get("FITS_HOME", "").strip()
    try:
        if not configured:
            bundled = Path(__file__).resolve().parent / "fits" / "tools" / "fits-1.6.0"
            if bundled.is_dir():
                configured = bundled
        if not configured:
            launcher_on_path = shutil.which(launcher_name)
            if not launcher_on_path:
                unavailable("NOT_CONFIGURED", "Set FITS_HOME to the extracted FITS directory, "
                            "restore fits/tools/fits-1.6.0, or add its launcher directory to PATH.")
                return None
            configured = Path(launcher_on_path).parent
        home = Path(configured).expanduser().resolve()
        if not home.is_dir():
            unavailable("INVALID_HOME", f"FITS directory does not exist: {home}")
            return None
        launcher = home / launcher_name
        if not launcher.is_file():
            unavailable("LAUNCHER_MISSING", f"Expected {launcher}. Select the extracted distribution root.")
            return None
        if not any((home / "lib").glob("*.jar")):
            unavailable("LIBRARIES_MISSING", f"No library JARs in {home / 'lib'}. Install the release ZIP, not source code.")
            return None
        java_home = os.environ.get("JAVA_HOME")
        java = (str(Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java"))
                if java_home else shutil.which("java"))
        if not java:
            unavailable("JAVA_UNAVAILABLE", "Java is not on PATH and JAVA_HOME is unset.")
            return None
        try:
            version = subprocess.run(
                [java, "-version"], shell=False, check=True, capture_output=True,
                text=True, errors="replace", timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            unavailable("JAVA_UNAVAILABLE", f"Cannot run Java at {java}: {exc}. Check JAVA_HOME/PATH.")
            return None
        logging.info("[FITS:READY] Directory=%s; launcher=%s; Java=%s; %s. "
                     "Pipeline invokes the Java entry point directly with the DROID-only profile.",
                     home, launcher, java, (version.stderr or version.stdout).strip())
        return home, java
    except (OSError, ValueError) as exc:
        unavailable("INVALID_HOME", f"Cannot inspect FITS configuration: {exc}")
        return None


def _read_fits_report(report):
    """Read complete FITS XML with the same validation in every execution path."""
    root = LET.parse(str(report), LET.XMLParser(resolve_entities=False, no_network=True)).getroot()
    if root.tag != f"{{{FITS_NS}}}fits":
        raise ValueError("FITS returned an unexpected XML root")
    return root


def identify_with_fits(file_path, fits_home, java=None):
    """Run FITS with the Pipeline DROID-only profile; return its complete XML."""
    if not FITS_PROFILE.is_file():
        raise FileNotFoundError(f"Pipeline FITS profile missing: {FITS_PROFILE}")
    fits_home = Path(fits_home).resolve()
    java_home = os.environ.get("JAVA_HOME")
    java = java or (str(Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")) if java_home else "java")
    with tempfile.TemporaryDirectory(prefix="pipeline-fits-") as temp_dir:
        report = Path(temp_dir) / "fits.xml"
        environment = os.environ.copy()
        environment["FITS_HOME"] = str(fits_home)
        subprocess.run(
            [java, "-classpath", str(fits_home / "lib" / "*"),
             "edu.harvard.hul.ois.fits.Fits", "-f", str(FITS_PROFILE),
             "-i", str(Path(file_path).resolve()),
             "-o", str(report)],
            cwd=str(fits_home), env=environment, shell=False, check=True,
            capture_output=True, text=True, errors="replace", timeout=300,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _read_fits_report(report)


class FitsInputChangedError(RuntimeError):
    """Identification inputs changed; the saved inventory must not be replaced."""


def _fits_windows_times(handle, access_ns=None):
    """Read Windows change time, or set access time without touching write time."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    if access_ns is not None:
        ticks = access_ns // 100 + 116444736000000000
        access = wintypes.FILETIME(ticks & 0xffffffff, ticks >> 32)
        function = kernel.SetFileTime
        function.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                             ctypes.POINTER(wintypes.FILETIME), ctypes.c_void_p]
        if not function(handle, None, ctypes.byref(access), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return

    class BasicInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_longlong) for name in
                    ("creation", "access", "write", "change")] + [("attributes", wintypes.DWORD)]

    info = BasicInfo()
    function = kernel.GetFileInformationByHandleEx
    function.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    if not function(handle, 0, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.change


def _fits_file_state(path):
    """Ignore read-induced access time; include identity and metadata change time."""
    with open(path, "rb") as stream:
        info = os.fstat(stream.fileno())
        change = info.st_ctime_ns
        if os.name == "nt":
            import msvcrt
            change = _fits_windows_times(msvcrt.get_osfhandle(stream.fileno()))
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, change)


def _fits_restore_access(path, access_ns, expected):
    """Restore access time on the same file, leaving modification time alone."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        close = kernel.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        # FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES; share read/write/delete.
        handle = create(str(path), 0x180, 7, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if _fits_file_state(path) != expected or _fits_windows_times(handle) != expected[4]:
                raise FitsInputChangedError(f"File changed before timestamp restoration: {path}")
            _fits_windows_times(handle, access_ns)
        finally:
            close(handle)
    else:
        with open(path, "rb") as stream:
            if _fits_file_state(path) != expected:
                raise FitsInputChangedError(f"File changed before timestamp restoration: {path}")
            # POSIX UTIME_OMIT avoids overwriting an external modification time.
            import ctypes
            import sys
            class Timespec(ctypes.Structure):
                _fields_ = [("seconds", ctypes.c_long), ("nanoseconds", ctypes.c_long)]
            times = (Timespec * 2)()
            times[0].seconds, times[0].nanoseconds = divmod(access_ns, 1000000000)
            times[1].nanoseconds = -2 if sys.platform == "darwin" else (1 << 30) - 2
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.futimens(stream.fileno(), times) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code), str(path))


class _FitsInputGuard:
    def __init__(self, root, xml_path, xml_bytes, xml_state, records):
        self.root, self.xml_path = root, xml_path
        self.xml_bytes, self.xml_state = xml_bytes, xml_state
        self.records = records
        self.by_path = {r["path"]: r for r in records if r["error"] is None}
        self.aliases = {}
        for record in records:
            if record["error"] is None:
                self.aliases.setdefault(record["state"][:2], []).append(record)
        self.touched = set()
        self.changed = set()
        self.directories = None

    def check(self):
        try:
            xml_unchanged = (_fits_file_state(self.xml_path) == self.xml_state
                             and self.xml_path.read_bytes() == self.xml_bytes)
        except OSError:
            xml_unchanged = False
        if not xml_unchanged:
            raise FitsInputChangedError("Accession XML changed during FITS; saved XML retained.")
        for record in self.records:
            if record.get("missing") and record["path"].exists():
                raise FitsInputChangedError(f"Missing accession file appeared during FITS: {record['path']}")
            if "state" not in record:
                continue
            path = record["path"]
            try:
                unchanged = (record["source"].resolve() == path
                             and _fits_file_state(path) == record["state"])
            except OSError:
                unchanged = False
            if not unchanged or path in self.changed:
                raise FitsInputChangedError(f"Accession file changed during FITS: {path}")
        if self.directories is not None:
            try:
                members, directories = _fits_directory_inventory(self.root)
            except (OSError, ValueError) as exc:
                raise FitsInputChangedError("Payload changed during FITS.") from exc
            if (members != {r["path"] for r in self.records}
                    or directories != self.directories):
                raise FitsInputChangedError("Payload membership changed during FITS; saved XML retained.")

    def restore(self):
        for path in list(self.touched):
            record = self.by_path[path]
            try:
                if record["source"].resolve() != path or _fits_file_state(path) != record["state"]:
                    self.changed.add(path)
                    logging.warning("[FITS:INPUT_CHANGED] %s; timestamps left untouched.", path)
                    continue
                _fits_restore_access(path, record["atime"], record["state"])
                after = _fits_file_state(path)
                if after[:4] != record["state"][:4]:
                    self.changed.add(path)
                else:
                    # An explicit access-time restoration can itself change ctime.
                    # Update aliases too, since hard links share their timestamps.
                    for alias in self.aliases[record["state"][:2]]:
                        alias["state"] = after
            except FitsInputChangedError:
                self.changed.add(path)
                logging.warning("[FITS:INPUT_CHANGED] %s; timestamps left untouched.", path)
            except OSError as exc:
                logging.warning("Could not restore timestamps after FITS for %s: %s", path, exc)
            finally:
                self.touched.discard(path)


def _fits_directory_inventory(root):
    """Enumerate without following links; reject uncertain directory-mode inputs."""
    members, directories = set(), {}

    def inspect(path):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"symlink or reparse point: {path}")
        return info

    def fail(error):
        raise error

    for directory, names, files in os.walk(root, followlinks=False, onerror=fail):
        directory = Path(directory)
        info = inspect(directory)
        directories[directory] = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
        for name in names:
            inspect(directory / name)
        for name in files:
            path = directory / name
            if not stat.S_ISREG(inspect(path).st_mode):
                raise ValueError(f"not a regular file: {path}")
            members.add(path.resolve())
    return members, directories


def _fits_batch_eligibility(root, records):
    if len(records) < 2:
        return None, "fewer than two inventory files"
    if any(r["error"] is not None for r in records):
        return None, "inventory contains invalid or unavailable entries"
    expected = {r["path"] for r in records}
    if len(expected) != len(records):
        return None, "duplicate inventory paths"
    try:
        members, directories = _fits_directory_inventory(root)
    except (OSError, ValueError) as exc:
        return None, str(exc)
    if members != expected:
        return None, f"directory membership differs from inventory ({len(members)} disk files, {len(expected)} inventory files)"
    return directories, None


def _stop_fits_batch(process):
    """Stop the launcher and its JVM before reading reports or restoring times."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True,
                timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode and process.poll() is None:
                raise RuntimeError("Could not terminate FITS process tree; accession XML retained.")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        # Never launch fallback work while an earlier JVM might still be alive.
        raise RuntimeError("Could not confirm FITS process-tree termination; accession XML retained.") from exc


def _identify_fits_batch(root, paths, fits_home, java, timeout, report_callback=None):
    """Return validated reports; failed/missing entries are retried per file."""
    home = Path(fits_home).resolve()
    if not FITS_PROFILE.is_file():
        raise FileNotFoundError(f"Pipeline FITS profile missing: {FITS_PROFILE}")
    with tempfile.TemporaryDirectory(prefix="pipeline-fits-batch-") as temporary:
        output = Path(temporary) / "reports"
        output.mkdir()
        expected = {output / (path.relative_to(root).as_posix() + ".fits.xml"): path for path in paths}
        pending_reports = set(expected)

        def poll_reports():
            written = 0
            for report, path in expected.items():
                if not report.is_file():
                    continue
                written += 1
                if report_callback is None or report not in pending_reports:
                    continue
                try:
                    _read_fits_report(report)
                except (OSError, LET.XMLSyntaxError, ValueError):
                    continue  # FITS may still be writing this report.
                pending_reports.remove(report)
                report_callback(path)
            return written
        environment = os.environ.copy()
        environment["FITS_HOME"] = str(home)
        command = [java, "-classpath", str(home / "lib" / "*"), "edu.harvard.hul.ois.fits.Fits",
                   "-f", str(FITS_PROFILE), "-i", str(root), "-o", str(output), "-r", "-n"]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            options = dict(cwd=str(home), env=environment, shell=False, stdout=stdout, stderr=stderr,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if os.name != "nt":
                options["start_new_session"] = True
            process = subprocess.Popen(command, **options)
            deadline = time.monotonic() + timeout
            timed_out = False
            finished = False
            reported = 0
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    try:
                        process.wait(timeout=min(0.25, remaining))
                        finished = True
                        break
                    except subprocess.TimeoutExpired:
                        written = poll_reports()
                        if written > reported:
                            logging.info("[FITS:BATCH_PROGRESS] %d/%d reports written; awaiting batch completion.", written, len(paths))
                            reported = written
            finally:
                # A single cleanup boundary covers deadlines, interruptions and
                # unexpected exceptions. Successful waits need no termination.
                if not finished:
                    _stop_fits_batch(process)
            if timed_out:
                logging.warning("[FITS:BATCH_TIMEOUT] Budget of %.1f seconds exceeded; retrying unresolved files.", timeout)
            if not timed_out and process.returncode:
                stderr.seek(0, os.SEEK_END)
                stderr.seek(max(0, stderr.tell() - 2000))
                diagnostic = stderr.read(2000).decode("utf-8", errors="replace")
                logging.warning("[FITS:BATCH_EXIT_ERROR] Exit code %s; retrying all files. %s", process.returncode, diagnostic)
                return {}
        actual = set(output.rglob("*"))
        if any(p.is_symlink() or getattr(p.lstat(), "st_file_attributes", 0) & 0x400
               or (not p.is_dir() and p not in expected) for p in actual):
            logging.warning("[FITS:BATCH_INVALID_OUTPUT] Unexpected report paths; retrying all files.")
            return {}
        results = {}
        for report, path in expected.items():
            try:
                # Re-read after termination; progress-time validation is not final.
                results[path] = _read_fits_report(report)
                if report_callback is not None and report in pending_reports:
                    pending_reports.remove(report)
                    report_callback(path)
            except (OSError, LET.XMLSyntaxError, ValueError) as exc:
                logging.warning("[FITS:BATCH_REPORT_ERROR] %s: %s; retrying per file.", path, exc)
        return results


def add_object_characteristics(premis_obj, checksum, size, fits_result=None):
    """Map FITS identities using DataAccessioner's PREMIS v2 conventions.

    Preserve the complete FITS report in an extension, including unmapped
    technical metadata, conflicts, tool output and identification warnings.
    """
    def element(parent, name, value=None):
        child = LET.SubElement(parent, f"{{{PREMIS_NS}}}{name}")
        child.text = value
        return child

    characteristics = element(premis_obj, "objectCharacteristics")
    element(characteristics, "compositionLevel", "0")
    fixity = element(characteristics, "fixity")
    element(fixity, "messageDigestAlgorithm", "SHA-256")
    element(fixity, "messageDigest", checksum)
    element(fixity, "messageDigestOriginator", "Pipeline (Python hashlib)")
    element(characteristics, "size", str(size))
    if fits_result is None:
        return

    ns = {"f": FITS_NS}
    for identity in fits_result.findall("f:identification/f:identity", ns):
        name = identity.get("format", "").strip()
        mime = identity.get("mimetype", "").strip()
        if (name.casefold() in ("", "unknown", "unknown binary")
                and mime in ("", "application/octet-stream")
                and not identity.findall("f:externalIdentifier", ns)):
            continue
        fmt = element(characteristics, "format")
        designation = element(fmt, "formatDesignation")
        element(designation, "formatName", identity.get("format", ""))
        versions = identity.findall("f:version", ns)
        if versions:
            element(designation, "formatVersion", " | ".join(v.text or "" for v in versions))
        for identifier in identity.findall("f:externalIdentifier", ns):
            key = (identifier.text or "").strip()
            if (identifier.get("type", "").casefold() == "puid"
                    or identifier.get("toolname", "").casefold() == "droid") and re.fullmatch(r"(?:x-)?fmt/\d+", key):
                registry = element(fmt, "formatRegistry")
                element(registry, "formatRegistryName", "http://www.nationalarchives.gov.uk/pronom")
                element(registry, "formatRegistryKey", key)
        # DataAccessioner places the MIME type in the first formatNote.
        element(fmt, "formatNote", identity.get("mimetype", ""))
        for tool in identity.findall("f:tool", ns):
            name = tool.get("toolname", "")
            version = tool.get("toolversion")
            element(fmt, "formatNote", f"Identified by: {name}" + (f" v{version}" if version else ""))
    extension = element(characteristics, "objectCharacteristicsExtension")
    extension.append(deepcopy(fits_result))


def generate_data_accessioner_xml(data_directory, output_folder, accession_number,
                                  move_files=False, clean_files_only=None, fits_home=None,
                                  fits_workers=2, progress_callback=None, *, fits_batch=True,
                                  fits_batch_timeout=None):
    """Ingest, then enrich the saved XML with FITS.

    Use ingest_accession() for baseline-only ingest, and
    enrich_accession_with_fits() to identify an existing unbagged accession.
    The progress callback reports identification in inventory order.
    """
    if fits_workers not in (1, 2):
        raise ValueError("fits_workers must be 1 or 2")
    if fits_batch_timeout is not None and (type(fits_batch_timeout) not in (int, float)
            or not 0 < fits_batch_timeout < float("inf")):
        raise ValueError("fits_batch_timeout must be a finite positive number")
    xml_path = ingest_accession(data_directory, output_folder, accession_number,
                                move_files, clean_files_only)
    return enrich_accession_with_fits(
        collection_directory(output_folder, accession_number), xml_path,
        fits_home=fits_home, fits_workers=fits_workers,
        progress_callback=progress_callback, fits_batch=fits_batch,
        fits_batch_timeout=fits_batch_timeout,
    )


def ingest_accession(data_directory, output_folder, accession_number,
                     move_files=False, clean_files_only=None, progress_callback=None):
    """Transfer files and write the baseline inventory without configuring FITS.

    Returns a new XML inventory in <output>/<accession>/<accession>_Docs/. UUIDs, sizes and SHA-256 digests are
    created here; enrich_accession_with_fits preserves them. This is a fresh
    ingest operation, not a resume/merge operation for an existing inventory.
    """
    data_directory  = Path(data_directory).resolve()
    output_folder   = Path(output_folder)
    if clean_files_only is not None:
        clean_files_only = {Path(path).resolve() for path in clean_files_only}
    if not data_directory.is_dir():
        raise ValueError("Ingest requires an existing source directory")
    wrapper = collection_directory(output_folder, accession_number)
    accession_folder = wrapper / data_directory.name
    if accession_folder.is_relative_to(data_directory.resolve()) or data_directory.resolve().is_relative_to(accession_folder):
        raise ValueError("Input Directory and accession directory must not contain one another.")
    if wrapper.exists():
        raise FileExistsError(f"Collection destination already exists; ingest will not overwrite it: {wrapper}")
    try:
        status = load_status(output_folder, accession_number)
    except FileNotFoundError:
        status = create_status(output_folder, accession_number, collection_name=data_directory.name, layout="unknown")
    if status["collection_name"] != data_directory.name:
        raise ValueError("Source collection name differs from the recorded accession collection")
    documentation_dir(output_folder, accession_number)
    accession_folder.mkdir(parents=True, exist_ok=True)

    dir_times = {}

    NSMAP = {
        None:     "http://dataaccessioner.org/schema/dda-1-1",
        "premis": "info:lc/xmlns/premis-v2",
    }

    collection_el = LET.Element("collection", nsmap=NSMAP)
    accession_el  = LET.SubElement(collection_el, "accession", number=accession_number)
    LET.SubElement(accession_el, "ingest_note").text = (
        f"Transferred on {datetime.now().isoformat()}"
    )

    total_files = (sum(1 for p in collection_paths(data_directory)
                       if p.is_file() and (clean_files_only is None or p in clean_files_only))
                   if progress_callback is not None else 0)
    completed = 0

    def report_progress(relative_path):
        if progress_callback is not None:
            try:
                progress_callback(completed + 1, total_files, relative_path.as_posix())
            except Exception:
                logging.warning("Could not update accession progress.", exc_info=True)

    def finish_file(dest_path, rel_path, checksum):
        file_el = LET.SubElement(
            accession_el, "file",
            name=(Path(data_directory.name) / rel_path).as_posix(),
            size=str(dest_path.stat().st_size),
            SHA256=checksum,
        )

        premis_obj = LET.SubElement(
            file_el, "{info:lc/xmlns/premis-v2}object", nsmap=NSMAP
        )
        premis_id = LET.SubElement(
            premis_obj, "{info:lc/xmlns/premis-v2}objectIdentifier"
        )
        LET.SubElement(
            premis_id, "{info:lc/xmlns/premis-v2}objectIdentifierType"
        ).text = "uuid"
        LET.SubElement(
            premis_id, "{info:lc/xmlns/premis-v2}objectIdentifierValue"
        ).text = str(uuid.uuid4())
        add_object_characteristics(premis_obj, checksum, dest_path.stat().st_size)

    for file_path in collection_paths(data_directory):

        # Record directory timestamps so we can restore them after copying
        if file_path.is_dir():
            stat = file_path.stat()
            rel  = file_path.relative_to(data_directory)
            dir_times[rel] = (stat.st_atime_ns, stat.st_mtime_ns)
            (accession_folder / rel).mkdir(parents=True, exist_ok=True)

        if not file_path.is_file():
            continue

        # Skip infected files when a filter is active
        if clean_files_only is not None and file_path not in clean_files_only:
            logging.warning(f"[SKIPPED — INFECTED] {file_path}")
            continue

        stat_src = file_path.stat()
        atime    = stat_src.st_atime
        mtime    = stat_src.st_mtime

        rel_path  = file_path.relative_to(data_directory)
        dest_path = accession_folder / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if os.path.lexists(dest_path):
            raise FileExistsError(f"Refusing to replace an existing collection file: {dest_path}")
        if move_files:
            shutil.move(str(file_path), str(dest_path))
        else:
            shutil.copy2(str(file_path), str(dest_path))

        # Restore original timestamps explicitly after copy
        os.utime(dest_path, ns=(stat_src.st_atime_ns, stat_src.st_mtime_ns))

        checksum = compute_sha256(dest_path)
        os.utime(dest_path, ns=(stat_src.st_atime_ns, stat_src.st_mtime_ns))
        report_progress(rel_path)
        finish_file(dest_path, rel_path, checksum)
        completed += 1

    xml_output_file = new_document(output_folder, f"{accession_number}.xml", accession_number)
    LET.ElementTree(collection_el).write(
        str(xml_output_file),
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=True,
    )

    # Restore directory timestamps (fix: loop must be indented correctly so
    # ALL directories are restored, not just the last one)
    for rel_path, (atime, mtime) in dir_times.items():
        dest_dir = accession_folder / rel_path
        if dest_dir.exists():
            try:
                os.utime(dest_dir, ns=(atime, mtime))
            except Exception:
                pass

    return xml_output_file


def enrich_accession_with_fits(accession_folder, xml_input, fits_home=None,
                               fits_workers=2, progress_callback=None, result_callback=None, *,
                               fits_batch=True, fits_batch_timeout=None):
    """Enrich an existing inventory in place without transferring or hashing.

    accession_folder is the accession directory, optionally already bagged. Only files listed in XML
    are identified. Successful results replace prior FITS-derived formats and
    FITS extension trees; failed files retain all existing metadata. Baseline
    attributes, UUIDs, fixity, size and unrelated metadata are left untouched.
    Returns xml_input. Optional result_callback receives per-attempt counts and
    outcome; historical XML is never used to infer this attempt's success.
    Bagged accessions resolve logical inventory paths under data/.
    Directory batching is enabled only for an exact inventory match. Set
    fits_batch=False for the original per-file launcher. The default batch
    timeout is 300 seconds per inventory file (no inactivity cutoff); callers
    can supply a positive fits_batch_timeout in seconds. Final progress and
    result counts include each file once, including per-file retries.
    Inputs must remain quiescent: detected changes abort XML replacement.
    """
    if fits_workers not in (1, 2):
        raise ValueError("fits_workers must be 1 or 2")
    if fits_batch_timeout is not None and (type(fits_batch_timeout) not in (int, float)
            or not 0 < fits_batch_timeout < float("inf")):
        raise ValueError("fits_batch_timeout must be a finite positive number")
    from pipeline_state import bag_layout, resolve_payload_root
    accession_folder = resolve_payload_root(accession_folder, bag_layout(accession_folder)).resolve()
    xml_input = Path(xml_input)
    xml_state = _fits_file_state(xml_input)
    xml_bytes = xml_input.read_bytes()
    if _fits_file_state(xml_input) != xml_state:
        raise FitsInputChangedError("Accession XML changed while being read.")
    tree = LET.ElementTree(LET.fromstring(xml_bytes, LET.XMLParser(resolve_entities=False, no_network=True)))
    files = tree.findall(".//{http://dataaccessioner.org/schema/dda-1-1}file")
    records = []
    for file_el in files:
        source = accession_folder / (file_el.get("name") or "")
        record = dict(file=file_el, source=source, path=source, error=None)
        try:
            path = source.resolve()
            path.relative_to(accession_folder)
            record["path"] = path
            if not path.is_file():
                record["missing"] = not path.exists()
                raise FileNotFoundError(f"Accession file missing: {path}")
            record["atime"] = path.stat().st_atime_ns
            record["state"] = _fits_file_state(path)
            if file_el.find(f"{{{PREMIS_NS}}}object/{{{PREMIS_NS}}}objectCharacteristics") is None:
                raise ValueError("File record has no baseline PREMIS characteristics")
        except (OSError, ValueError) as exc:
            record["error"] = exc
        records.append(record)
    guard = _FitsInputGuard(accession_folder, xml_input, xml_bytes, xml_state, records)
    fits_config = configure_fits(fits_home)
    completed = 0
    progressed = set()
    counts = dict(file_count=len(files), identified_count=0, unidentified_count=0,
                  error_count=0, unavailable_count=0)

    def advance_progress(file_el):
        nonlocal completed
        if id(file_el) in progressed:
            return
        progressed.add(id(file_el))
        completed += 1
        if progress_callback is not None:
            try:
                progress_callback(completed, len(files), file_el.get("name"))
            except Exception:
                logging.warning("Could not update accession progress.", exc_info=True)

    def finish_file(file_el, dest_path, future, fits_result):
        advance_progress(file_el)
        if future is None and fits_result is None:
            counts["unavailable_count" if fits_config is None else "error_count"] += 1
            return
        try:
            if fits_result is None:
                fits_result = future.result()
        except subprocess.TimeoutExpired:
            counts["error_count"] += 1
            logging.warning("[FITS:TIMEOUT] %s exceeded 300 seconds; existing metadata retained.", dest_path)
            return
        except subprocess.CalledProcessError as exc:
            counts["error_count"] += 1
            logging.warning("[FITS:EXIT_ERROR] %s; exit code %s; %s", dest_path, exc.returncode,
                            (exc.stderr or exc.stdout or "No diagnostic output")[-2000:])
            return
        except (LET.XMLSyntaxError, ValueError) as exc:
            counts["error_count"] += 1
            logging.warning("[FITS:INVALID_XML] %s: %s", dest_path, exc)
            return
        except (OSError, subprocess.SubprocessError) as exc:
            counts["error_count"] += 1
            logging.warning("[FITS:EXECUTION_ERROR] %s: %s", dest_path, exc)
            return
        characteristics = file_el.find(f"{{{PREMIS_NS}}}object/{{{PREMIS_NS}}}objectCharacteristics")
        _replace_fits_metadata(characteristics, fits_result)
        formats = characteristics.findall(f"{{{PREMIS_NS}}}format")
        puids = characteristics.findall(f".//{{{PREMIS_NS}}}formatRegistryKey")
        counts["identified_count" if formats else "unidentified_count"] += 1
        if formats:
            logging.info("[FITS:IDENTIFIED] %s; %d format(s); PUIDs: %s", dest_path,
                         len(formats), ", ".join(p.text for p in puids) or "none reported")
        else:
            logging.info("[FITS:NO_IDENTIFICATION] %s; FITS completed but returned no useful "
                         "format identification. Raw FITS XML retained.", dest_path)

    batch_results = {}
    try:
        if fits_config and fits_batch:
            directories, reason = _fits_batch_eligibility(accession_folder, records)
            if reason is not None:
                logging.info("[FITS:BATCH_INELIGIBLE] %s; using per-file identification for %d files.", reason, len(files))
            else:
                guard.directories = directories
                guard.check()
                timeout = fits_batch_timeout if fits_batch_timeout is not None else 300 * len(files)
                logging.info("[FITS:BATCH_START] %d inventory files; timeout %.1f seconds; no inactivity cutoff.", len(files), timeout)
                guard.touched.update(r["path"] for r in records)
                ready = set()
                def report_ready(path):
                    ready.add(path)
                    while completed < len(records) and records[completed]["path"] in ready:
                        advance_progress(records[completed]["file"])
                try:
                    batch_results = _identify_fits_batch(
                        accession_folder, [r["path"] for r in records], *fits_config, timeout, report_ready)
                except (OSError, subprocess.SubprocessError, LET.XMLSyntaxError, ValueError) as exc:
                    logging.warning("[FITS:BATCH_ERROR] %s; retrying per file.", exc)
                finally:
                    guard.restore()
                guard.check()
                logging.info("[FITS:BATCH_RESULT] %d/%d valid reports; %d per-file retries.",
                             len(batch_results), len(files), len(files) - len(batch_results))
        elif fits_config:
            logging.info("[FITS:BATCH_DISABLED] Using per-file identification for %d files.", len(files))

        pending = deque()
        with ThreadPoolExecutor(max_workers=fits_workers) as executor:
            for record in records:
                file_el, dest_path = record["file"], record["path"]
                future = None
                if fits_config:
                    if record["error"] is not None:
                        logging.warning("[FITS:EXECUTION_ERROR] %s: %s", dest_path, record["error"])
                    elif dest_path not in batch_results:
                        guard.touched.add(dest_path)
                        future = executor.submit(identify_with_fits, dest_path, *fits_config)
                pending.append((file_el, dest_path, future, batch_results.get(dest_path)))
                if len(pending) >= (fits_workers if fits_config else 1):
                    finish_file(*pending.popleft())
            while pending:
                finish_file(*pending.popleft())
    finally:
        guard.restore()

    if fits_config:
        # Replace only after serialization succeeds, preserving the saved baseline
        # if writing the enriched document fails.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=xml_input.parent, prefix=xml_input.name + ".",
                                             suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                tree.write(stream, encoding="UTF-8", xml_declaration=True, pretty_print=True)
            # Recheck after serialization too, before replacing any saved XML.
            guard.check()
            os.replace(temporary, xml_input)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
    if result_callback is not None:
        outcome = ("empty" if not files else "unavailable" if counts["unavailable_count"] else
                   "partial" if counts["error_count"] else
                   "identified" if counts["identified_count"] else "unidentified")
        result_callback(dict(outcome=outcome, **counts))
    return xml_input


def _replace_fits_metadata(characteristics, fits_result):
    """Replace only formats derived from embedded FITS and FITS extension data.

    Reuse the existing mapper on a scratch object. Matching against the previous
    embedded report avoids deleting manually supplied, unrelated format entries.
    """
    def mapped_formats(result):
        scratch = LET.Element(f"{{{PREMIS_NS}}}object")
        add_object_characteristics(scratch, "", 0, result)
        return scratch.find(f"{{{PREMIS_NS}}}objectCharacteristics")

    def signature(node):
        return (node.tag, tuple(sorted(node.attrib.items())), (node.text or "").strip(),
                tuple(signature(child) for child in node))

    replacement = mapped_formats(fits_result)
    for extension in list(characteristics.findall(f"{{{PREMIS_NS}}}objectCharacteristicsExtension")):
        previous_reports = list(extension.findall(f"{{{FITS_NS}}}fits"))
        for old_fits in previous_reports:
            old_formats = mapped_formats(old_fits)
            for old_format in old_formats.findall(f"{{{PREMIS_NS}}}format"):
                for current in list(characteristics.findall(f"{{{PREMIS_NS}}}format")):
                    if signature(current) == signature(old_format):
                        characteristics.remove(current)
                        break
            extension.remove(old_fits)
        if previous_reports and len(extension) == 0 and not extension.attrib and not (extension.text or "").strip():
            characteristics.remove(extension)
    # PREMIS formats precede extensions (and other later characteristics).
    position = next((i for i, child in enumerate(characteristics)
                     if child.tag not in {f"{{{PREMIS_NS}}}{name}" for name in
                                          ("compositionLevel", "fixity", "size", "format")}),
                    len(characteristics))
    for fmt in replacement.findall(f"{{{PREMIS_NS}}}format"):
        characteristics.insert(position, fmt)
        position += 1
    characteristics.append(replacement.find(f"{{{PREMIS_NS}}}objectCharacteristicsExtension"))


# ==========================
# XSLT PROCESSOR
# ==========================

def run_xslt_processor(xml_input, xslt_file, output_file):
    """Transform xml_input with xslt_file and write result to output_file."""
    xml_tree  = LET.parse(str(xml_input))
    xslt_tree = LET.parse(str(xslt_file))
    transform = LET.XSLT(xslt_tree)
    result    = transform(xml_tree)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(str(result))

    return output_file


# ==========================
# BAGIT PACKAGER
# ==========================

def _write_aptrust_info(bag_dir, title, access, storage_option, description=""):
    """
    Write aptrust-info.txt into the bag root and regenerate tagmanifest-sha256.txt
    so the new file is properly checksummed.

    APTrust requires this custom tag file in addition to the standard bag-info.txt.
    """
    if access not in APTRUST_ACCESS_VALUES:
        raise ValueError(
            f"APTrust Access must be one of {APTRUST_ACCESS_VALUES}, got '{access}'"
        )
    if storage_option not in APTRUST_STORAGE_OPTIONS:
        raise ValueError(
            f"APTrust Storage-Option must be one of {APTRUST_STORAGE_OPTIONS}, "
            f"got '{storage_option}'"
        )

    aptrust_info_path = Path(bag_dir) / "aptrust-info.txt"
    lines = [
        f"Title: {title}",
        f"Access: {access}",
        f"Storage-Option: {storage_option}",
    ]
    if description:
        lines.append(f"Description: {description}")

    with open(aptrust_info_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # Regenerate tag manifest to include aptrust-info.txt
    tag_manifest_path = Path(bag_dir) / "tagmanifest-sha256.txt"
    tag_files = ["bagit.txt", "bag-info.txt", "aptrust-info.txt", "manifest-sha256.txt"]
    tag_manifest_lines = []
    for tag_file in tag_files:
        tf_path = Path(bag_dir) / tag_file
        if tf_path.exists():
            tag_manifest_lines.append(f"{compute_sha256(tf_path)}  {tag_file}")

    with open(tag_manifest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(tag_manifest_lines) + "\n")

    logging.info(f"aptrust-info.txt written and tag manifest updated at: {bag_dir}")


def _bag_preflight(accession_folder, accession_number, contact_name, contact_email,
                   source_organization, profile, title, access, storage_option,
                   description, xml_manifest):
    """Return the payload root, entries and verified SHA-256 digests without writing files."""
    if not BAGIT_AVAILABLE:
        raise RuntimeError("bagit-python is not installed.")
    root = Path(accession_folder)
    if root.is_symlink() or root.is_junction():
        raise ValueError("Accession root must not be a symbolic link or junction.")
    if not root.is_dir():
        raise ValueError(f"Accession directory does not exist or is not a directory: {root}")
    root = root.resolve()
    if profile not in ("generic", "aptrust"):
        raise ValueError(f"Unknown BagIt profile: {profile!r}")
    for name, value in {
        "accession_number": accession_number, "contact_name": contact_name,
        "contact_email": contact_email, "source_organization": source_organization,
        "title": title, "access": access, "storage_option": storage_option,
        "description": description,
    }.items():
        if not isinstance(value, str) or any(c in value for c in "\r\n\0"):
            raise ValueError(f"{name} must be a single-line string without NUL characters.")
        value.encode("utf-8")
    if not accession_number.strip():
        raise ValueError("Accession number is required.")
    if profile == "aptrust":
        if not title.strip() or not source_organization.strip():
            raise ValueError("APTrust requires Title and Source-Organization before construction.")
        if access not in APTRUST_ACCESS_VALUES:
            raise ValueError(f"Invalid APTrust Access: {access!r}")
        if storage_option not in APTRUST_STORAGE_OPTIONS:
            raise ValueError(f"Invalid APTrust Storage-Option: {storage_option!r}")

    entries = sorted(entry for entry in root.iterdir() if not is_managed_documentation(entry))
    reserved = {"data", "bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"}
    for entry in entries:
        name = entry.name.casefold()
        if name in reserved or re.fullmatch(r"(?:tag)?manifest-.*\.txt", name):
            raise ValueError(f"Existing or ambiguous BagIt layout: {entry.name!r}. "
                             "Construction will not rebuild or relocate an existing bag.")
    if not os.access(root, os.W_OK):
        raise PermissionError(f"Accession directory is not writable: {root}")

    payload = {}
    seen = set()

    # Do not follow links/reparse directories: they could escape the accession
    # or change meaning when relocated. Reject names this manifest writer cannot
    # represent unambiguously rather than silently encoding a different path.
    for directory, directories, filenames in collection_walk(root):
        for name in sorted(directories + filenames):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or path.is_junction():
                raise ValueError(f"Links/junctions in accession files are not supported: {rel}")
            if any(c in rel for c in "\r\n\\%") or any(part != part.strip() for part in rel.split("/")):
                raise ValueError(f"Unsupported manifest path: {rel!r}")
            rel.encode("utf-8")
            if rel.casefold() in seen:
                raise ValueError(f"Case-insensitive accession file path collision: {rel}")
            seen.add(rel.casefold())
            if path.is_file():
                payload[rel] = path
            elif not path.is_dir():
                raise ValueError(f"Unsupported accession entry: {rel}")

    baseline = None
    if xml_manifest is not None:
        try:
            tree = LET.parse(str(xml_manifest), LET.XMLParser(resolve_entities=False, no_network=True))
            ns = {"d": "http://dataaccessioner.org/schema/dda-1-1"}
            if tree.getroot().tag != "{http://dataaccessioner.org/schema/dda-1-1}collection":
                raise ValueError("Expected a Data Accessioner collection XML baseline")
            baseline = {}
            for record in tree.xpath("//d:file", namespaces=ns):
                name = record.get("name", "")
                algorithm, digest = stored_checksum(record)
                if (not name or "\\" in name or ":" in name
                        or any(part in ("", ".", "..") for part in name.split("/"))):
                    raise ValueError(f"Invalid baseline relative path: {name!r}")
                if name in baseline:
                    raise ValueError(f"Duplicate baseline file record: {name}")
                baseline[name] = (algorithm, digest)
        except (OSError, LET.XMLSyntaxError, ValueError) as exc:
            raise ValueError(f"Cannot verify supplied XML baseline: {exc}") from exc
        missing = sorted(set(baseline) - set(payload))
        extra = sorted(set(payload) - set(baseline))
        if missing or extra:
            raise ValueError(f"Accession contents differ from XML baseline; missing={missing}; unexpected={extra}")

    checksums = {}
    for rel, path in sorted(payload.items()):
        digest = compute_sha256(path)
        if baseline is not None and compute_checksum(path, baseline[rel][0]) != baseline[rel][1]:
            raise ValueError(f"Baseline checksum mismatch: {rel}. Construction refused before moving accession files.")
        checksums[rel] = digest
    logging.info("BagIt preflight passed: %d accession files; %s.", len(checksums),
                 "XML baseline verified" if baseline is not None else "fresh SHA-256 digests (no XML baseline supplied)")
    return root, entries, checksums


def construct_bag(accession_folder, accession_number, contact_name="", contact_email="",
                  source_organization="", profile="generic", title="",
                  access="Institution", storage_option="Standard", description="",
                  xml_manifest=None):
    """Construct an unbagged accession in place; return its resolved Path.

    Reject existing/ambiguous bags and verify a supplied XML baseline before
    mutation. Without XML, hash the current payload. Never validate or serialize.
    Exceptions propagate. Unexpected I/O failures can leave partial construction;
    there is no rollback or automatic retry. Keep payload quiescent throughout.
    """
    root, entries, checksums = _bag_preflight(
        accession_folder, accession_number, contact_name, contact_email,
        source_organization, profile, title, access, storage_option, description,
        xml_manifest,
    )
    metadata = {
        "Bag-Software-Agent": "bagit-python",
        "Bagging-Date": datetime.now().strftime("%Y-%m-%d"),
        "External-Identifier": accession_number,
    }
    for key, value in (("Contact-Name", contact_name), ("Contact-Email", contact_email),
                       ("Source-Organization", source_organization)):
        if value:
            metadata[key] = value
    if profile == "aptrust":
        metadata["BagIt-Profile-Identifier"] = APTRUST_PROFILE_IDENTIFIER

    try:
        data_dir = root / "data"
        data_dir.mkdir()  # Never reuse a destination that appeared after preflight.
        for item in entries:
            destination = data_dir / item.name
            if os.path.lexists(destination):
                raise FileExistsError(f"Accession file destination already exists: {destination}")
            shutil.move(str(item), str(destination))
        (root / "bagit.txt").write_text(
            "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n", encoding="utf-8")
        (root / "bag-info.txt").write_text(
            "".join(f"{key}: {value}\n" for key, value in metadata.items()), encoding="utf-8")
        (root / "manifest-sha256.txt").write_text(
            "".join(f"{digest}  data/{rel}\n" for rel, digest in checksums.items()), encoding="utf-8")
        tags = ("bagit.txt", "bag-info.txt", "manifest-sha256.txt")
        (root / "tagmanifest-sha256.txt").write_text(
            "".join(f"{compute_sha256(root / name)}  {name}\n" for name in tags), encoding="utf-8")
        if profile == "aptrust":
            _write_aptrust_info(root, title, access, storage_option, description)
    except Exception:
        logging.exception("BagIt construction failed at %s. The accession may be partially "
                          "modified; do not rerun construction or attempt automatic recovery.", root)
        raise
    logging.info("BagIt construction complete: %s", root)
    return root


def serialize_bag_to_tar(bag_path, *, overwrite=False):
    """Serialize a fresh, versioned collection and documentation snapshot.

    The legacy overwrite argument is accepted for compatibility but never permits
    replacement. Check basic structure, not checksums or APTrust compliance. Does not
    construct, validate, move payload or regenerate manifests. Failed writes or
    publication preserve previous TARs; the bag must remain unchanged meanwhile.
    """
    root = Path(bag_path).resolve()
    if (not root.is_dir() or not (root / "data").is_dir()
            or not (root / "bagit.txt").is_file()
            or not any(p.is_file() for p in root.glob("manifest-*.txt"))):
        raise ValueError(f"Expected an existing BagIt directory: {root}")
    parent = root.parent
    status = load_status(parent.parent, parent.name)
    if collection_directory(parent.parent, parent.name) != root:
        raise ValueError("TAR requires the accession collection wrapper")
    docs = documentation_dir(parent.parent, parent.name)
    tar_path = parent / (parent.name + ".tar")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=root.parent, prefix=tar_path.name + ".",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
        with tarfile.open(temporary, "w") as archive:
            archive.add(root, arcname=f"{parent.name}/{root.name}")
            archive.add(docs, arcname=f"{parent.name}/{docs.name}")
        # Publish only a fully written archive. Hard-link creation is atomic and
        # fails for any occupied name (including directories and dangling links).
        # Never fall back to replacement on filesystems without hard-link support.
        version = 1
        while True:
            tar_path = parent / (parent.name + (f"_v{version}" if version > 1 else "") + ".tar")
            if os.path.lexists(tar_path):
                version += 1
                continue
            try:
                os.link(temporary, tar_path)
                break
            except FileExistsError:
                version += 1
        logging.info("Selected preservation package output: %s", tar_path)
    except Exception:
        logging.exception("TAR serialization failed for %s; previous deliverable retained.", root)
        raise
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                logging.warning("Could not remove temporary TAR: %s", temporary, exc_info=True)
    logging.info("Bag serialized to tar: %s", tar_path)
    return tar_path


def create_bag(accession_folder, accession_number, contact_name="", contact_email="",
               source_organization="", profile="generic", title="",
               access="Institution", storage_option="Standard",
               description="", serialize_tar=False, validate=False,
               xml_manifest=None):
    """Construct, optionally validate, and optionally serialize a collection bag.

    Return (bag_path, tar_path, bag_valid, bag_error); bag_valid is None if not
    requested. Requested validation failure blocks TAR creation. As before,
    this wrapper serializes only APTrust bags. Construction errors propagate.
    """
    if not BAGIT_AVAILABLE:
        logging.warning("bagit-python is not installed. BagIt packaging skipped.")
        return None, None, False, "bagit-python is not installed."
    bag_root = construct_bag(
        accession_folder, accession_number, contact_name=contact_name,
        contact_email=contact_email, source_organization=source_organization,
        profile=profile, title=title, access=access, storage_option=storage_option,
        description=description, xml_manifest=xml_manifest,
    )
    bag_valid, bag_error = None, ""
    if validate:
        bag_valid, bag_error = validate_bag(bag_root)
        if bag_valid:
            logging.info("BagIt bag validated successfully: %s", bag_root)
        else:
            logging.warning("BagIt validation failed; TAR serialization blocked: %s", bag_error)
    tar_path = None
    if serialize_tar and profile == "aptrust" and (not validate or bag_valid):
        tar_path = serialize_bag_to_tar(bag_root)
    return bag_root, tar_path, bag_valid, bag_error


def validate_bag(bag_path, result_callback=None):
    """
    Validate an existing BagIt bag directory.
    Returns (is_valid: bool, error_message: str).
    Optional result_callback distinguishes invalid findings from execution or
    dependency errors without changing the two-value return contract.
    """
    if not BAGIT_AVAILABLE:
        if result_callback is not None:
            result_callback(dict(state="failed", outcome="indeterminate", valid=None,
                                 message="bagit-python is not installed."))
        return False, "bagit-python is not installed."
    try:
        bag = bagit.Bag(str(bag_path))
        bag.validate()
        if result_callback is not None:
            result_callback(dict(state="completed", outcome="valid", valid=True))
        return True, ""
    except bagit.BagValidationError as exc:
        if result_callback is not None:
            result_callback(dict(state="completed", outcome="invalid", valid=False, message=str(exc)))
        return False, str(exc)
    except Exception as exc:
        if result_callback is not None:
            result_callback(dict(state="failed", outcome="indeterminate", valid=None, message=str(exc)))
        return False, str(exc)


# ==========================
# FIXITY CHECKER
# ==========================

def run_fixity(xml_input, output_folder, accession_number):
    """
    Verify algorithm-identified checksums recorded in the XML manifest against files on disk.
    Resolve logical inventory paths inside data/ for an existing BagIt package.
    Writes CSV and LOG reports to <output>/<accession>/<accession>_Docs/.
    """
    output_folder    = Path(output_folder)
    from pipeline_state import bag_layout, resolve_payload_root
    accession = collection_directory(output_folder, accession_number)
    accession_folder = resolve_payload_root(accession, bag_layout(accession))

    log_file = new_document(output_folder, f"fixity_{accession_number}.log", accession_number)
    csv_file = new_document(output_folder, f"fixity_{accession_number}.csv", accession_number)

    # Use an isolated named logger so the pipeline's root logger is not disturbed
    fixity_log = logging.getLogger(f"fixity.{accession_number}")
    fixity_log.setLevel(logging.INFO)
    fixity_log.handlers.clear()
    fh = logging.FileHandler(log_file, "w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    fixity_log.addHandler(fh)
    fixity_log.propagate = False  # do not bubble up to root logger

    tree    = LET.parse(str(xml_input))
    root_el = tree.getroot()
    results = []

    for file_el in root_el.xpath(
        "//default:file",
        namespaces={"default": "http://dataaccessioner.org/schema/dda-1-1"}
    ):
        rel        = Path(file_el.get("name"))
        file_path  = accession_folder / rel
        algorithm, stored_digest = "", ""

        status       = "OK"
        computed_digest = ""
        error        = ""

        try:
            algorithm, stored_digest = stored_checksum(file_el)
            if not file_path.resolve().is_relative_to(accession_folder.resolve()):
                raise ValueError("Baseline path escapes accession")
            if not file_path.exists():
                status = "MISSING"
                error  = "File not found"
            else:
                computed_digest = compute_checksum(file_path, algorithm)
                if computed_digest != stored_digest:
                    status = "MISMATCH"
        except Exception as exc:
            status = "ERROR"
            error  = str(exc)

        results.append({
            "file_path":    str(file_path),
            "algorithm": algorithm,
            "stored_checksum":   stored_digest or "",
            "computed_checksum": computed_digest or "",
            "status":       status,
            "error":        error,
        })
        fixity_log.info("[%s] %s algorithm=%s stored=%s computed=%s error=%s",
                        status, file_path, algorithm, stored_digest, computed_digest, error)

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["file_path", "algorithm", "stored_checksum", "computed_checksum", "status", "error"]
        )
        writer.writeheader()
        writer.writerows(results)

    fh.close()
    fixity_log.removeHandler(fh)

    return csv_file, log_file


# ==========================
# SUMMARY REPORT
# ==========================

def generate_summary_report(csv_file, output_folder, accession_number):
    """
    Read the XSLT-transformed CSV and produce a plain-text summary of
    file extension counts, total size, and guessed MIME types.
    """
    ext_counter  = Counter()
    mime_counter = Counter()
    total_size   = 0

    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext = row.get("file extension", "").lower()
            if ext:
                ext_counter[ext] += 1

            try:
                total_size += int(row.get("size (bytes)", 0))
            except Exception:
                pass

            mime = mimetypes.guess_type(row.get("file name", ""))[0]
            if mime:
                mime_counter[mime] += 1

    output_txt = new_document(output_folder, f"{accession_number}.txt", accession_number)

    with open(output_txt, "w", encoding="utf-8") as f:
        f.write(f"Accession: {accession_number}\n\n")

        f.write("File Extension Counts:\n")
        for k, v in ext_counter.items():
            f.write(f"  {k}: {v}\n")

        f.write(f"\nTotal Size: {total_size / 1024:.2f} KB\n")

        f.write("\nMIME Type Counts (guessed):\n")
        for k, v in mime_counter.items():
            f.write(f"  {k}: {v}\n")

    return output_txt
