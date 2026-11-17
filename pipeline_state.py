"""Accession workflow state: storage, presentation, freshness, recording, and resume.

Processing operations remain in pipeline.py; this module tracks their history
and plans safe reuse without executing them.
"""
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from lxml import etree as ET

def document_path(output, accession, stage, key, filename, status=None):
    """Resolve a current report, including its collision-safe recorded filename."""
    root = Path(output).resolve()
    docs = docs_path(root, accession)
    if status is None:
        try:
            status = load_status(root, accession)
        except FileNotFoundError:
            status = None
    value = status["steps"][stage]["outputs"].get(key) if status else None
    path = root / value if isinstance(value, str) and value else docs / filename
    if path.resolve().parent != docs.resolve() or path.is_symlink():
        raise StatusValidationError("Documentation must be stored inside this accession's documentation directory")
    return path


XSLT_DIR = Path(__file__).resolve().parent / "resources" / "xslt"


# ============================================================================
# Status schema and atomic storage
# ============================================================================

STAGE_IDS = (
    "antivirus", "ingest", "fits", "reports", "summary", "fixity",
    "bag_construct", "bag_validate", "tar_serialize",
)
STATES = {"not_started", "running", "completed", "failed", "interrupted", "unknown"}
FRESHNESS_STATES = {"current", "stale", "unverified"}
LAYOUTS = {"unbagged", "bagged", "ambiguous", "unknown"}


class StatusValidationError(ValueError):
    """Malformed JSON, invalid schema, or mismatched accession identity."""


class UnsupportedSchemaError(StatusValidationError):
    """A status record requires a newer schema reader/writer."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_component(accession_number):
    # Apply Windows component rules even when read on another operating system.
    if (not isinstance(accession_number, str) or not accession_number
            or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', accession_number)
            or accession_number != accession_number.strip()
            or accession_number in (".", "..") or accession_number.endswith((".", " "))
            or accession_number.split(".")[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}):
        raise StatusValidationError("Accession number must be a single safe path component")


def _accession_root(output_folder, accession_number):
    _safe_component(accession_number)
    if ".." in accession_number:
        raise StatusValidationError("Accession number must not contain traversal sequences")
    root = Path(output_folder).resolve()
    accession = root / accession_number
    if accession.resolve().parent != root or accession.is_symlink() or accession.is_junction():
        raise StatusValidationError("Accession path resolves outside the output directory")
    return accession


DOC_MARKER = ".archives-pipeline-doc"


def is_managed_documentation(path):
    path = Path(path)
    marker = path / DOC_MARKER
    return (path.name.casefold() == f"{path.parent.name}_Docs".casefold() and not path.is_symlink()
            and not path.is_junction() and marker.is_file() and not marker.is_symlink())


def docs_path(output_folder, accession_number):
    """Read-only canonical documentation path with containment checks."""
    accession = _accession_root(output_folder, accession_number)
    docs = accession / f"{accession_number}_Docs"
    if docs.is_symlink() or docs.is_junction() or docs.resolve().parent != accession.resolve():
        raise StatusValidationError("Accession documentation must be a directory inside the accession directory")
    return docs


def documentation_dir(output_folder, accession_number):
    docs = docs_path(output_folder, accession_number)
    try:
        load_status(output_folder, accession_number)
    except FileNotFoundError:
        pass
    if docs.exists() and not is_managed_documentation(docs):
        raise StatusValidationError(f"Unmanaged or unsupported output directory: {docs}. Original content was left unchanged.")
    docs.mkdir(parents=True, exist_ok=True)
    marker = docs / DOC_MARKER
    if not marker.exists():
        with marker.open("x", encoding="utf-8") as stream:
            stream.write("Archives Pipeline documentation; excluded from collection payload.\n")
    return docs


def collection_directory(output, accession):
    """The accession's fixed collection wrapper, independent of the source name."""
    parent = _accession_root(output, accession)
    path = parent / f"{accession}_Collection"
    if path.resolve().parent != parent or path.is_symlink() or path.is_junction():
        raise StatusValidationError("Collection path resolves outside the accession directory")
    return path


def collection_walk(root):
    """Walk content, excluding only a marked top-level documentation directory."""
    root = Path(root)
    def walk_error(exc):
        raise exc
    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        if Path(directory) == root:
            directories[:] = [name for name in directories
                              if not is_managed_documentation(root / name)]
        yield directory, directories, files


def collection_paths(root):
    for directory, directories, files in collection_walk(root):
        for name in directories + files:
            yield Path(directory) / name


def _status_path(output_folder, accession_number):
    path = docs_path(output_folder, accession_number) / f"{accession_number}_status.json"
    if path.is_symlink():
        raise StatusValidationError("Status JSON must not be a symbolic link")
    return path


def _timestamp(value, name, nullable=False):
    if nullable and value is None:
        return
    try:
        if not isinstance(value, str):
            raise ValueError()
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise StatusValidationError(f"{name} must be an ISO-8601 timestamp with timezone") from exc


def _choice(value, choices, name):
    if not isinstance(value, str) or value not in choices:
        raise StatusValidationError(f"Invalid {name}: {value!r}")


def _integer(value, minimum, name):
    if type(value) is not int or value < minimum:
        raise StatusValidationError(f"{name} must be an integer >= {minimum}")


def _validate(status, accession_number):
    if not isinstance(status, dict):
        raise StatusValidationError("Status must be an object")
    version = status.get("schema_version")
    _integer(version, 1, "schema_version")
    if version > 2:
        raise UnsupportedSchemaError(f"Newer unsupported status schema: {version}")
    if version != 2:
        raise UnsupportedSchemaError("Unsupported previous output structure; use a new accession directory. No migration is performed.")
    required = {"collection_name", "revision", "accession_number", "accession_path", "created_at",
                "updated_at", "layout", "steps"}
    if not required <= status.keys():
        raise StatusValidationError("Missing required status fields")
    if status["accession_number"] != accession_number or status["accession_path"] != accession_number:
        raise StatusValidationError("Embedded accession identity does not match requested accession")
    _safe_component(status["collection_name"])
    _integer(status["revision"], 1, "revision")
    _timestamp(status["created_at"], "created_at")
    _timestamp(status["updated_at"], "updated_at")
    _choice(status["layout"], LAYOUTS, "layout")
    steps = status["steps"]
    if not isinstance(steps, dict) or not set(STAGE_IDS) <= steps.keys():
        raise StatusValidationError("All nine internal stages are required")
    fields = {"state", "outcome", "attempt", "started_at", "finished_at", "freshness",
              "settings", "inputs", "outputs", "evidence", "result"}
    for stage in STAGE_IDS:
        step = steps[stage]
        if not isinstance(step, dict) or not fields <= step.keys():
            raise StatusValidationError(f"Missing required fields for {stage}")
        _choice(step["state"], STATES, f"{stage}.state")
        outcome = step["outcome"]
        if outcome is not None and (not isinstance(outcome, str) or
                                   not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", outcome)):
            raise StatusValidationError(f"{stage}.outcome must be null or a safe string token")
        _integer(step["attempt"], 0, f"{stage}.attempt")
        for name in ("started_at", "finished_at"):
            _timestamp(step[name], f"{stage}.{name}", nullable=True)
        fresh = step["freshness"]
        if not isinstance(fresh, dict) or not {"state", "checked_at", "method", "reasons"} <= fresh.keys():
            raise StatusValidationError(f"Invalid {stage}.freshness")
        _choice(fresh["state"], FRESHNESS_STATES, f"{stage}.freshness.state")
        _timestamp(fresh["checked_at"], f"{stage}.freshness.checked_at", nullable=True)
        if not isinstance(fresh["method"], str) or not fresh["method"].strip():
            raise StatusValidationError("Freshness method must be a nonempty string")
        if not isinstance(fresh["reasons"], list) or not all(isinstance(r, str) for r in fresh["reasons"]):
            raise StatusValidationError("Freshness reasons must be a list of strings")
        for name in ("settings", "inputs", "outputs", "evidence", "result"):
            if not isinstance(step[name], dict):
                raise StatusValidationError(f"{stage}.{name} must be an object")


def _write(path, status):
    # Serialize first so serialization errors never touch the destination.
    try:
        serialized = json.dumps(status, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (ValueError, TypeError) as exc:
        raise StatusValidationError(f"Status is not valid JSON: {exc}") from exc
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=f".{path.name}.",
                                         suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def create_status(output_folder, accession_number, *, layout="unbagged", collection_name=None):
    """Create a record with explicit layout; refuse to replace any existing file.

    Default remains unbagged for new managed accessions. A first managed run of
    existing artifacts can supply unknown without inferring execution history.
    """
    path = _status_path(output_folder, accession_number)
    if path.exists():
        raise FileExistsError(path)
    parent = _accession_root(output_folder, accession_number)
    if parent.exists() and any(not is_managed_documentation(entry) for entry in parent.iterdir()):
        raise StatusValidationError("Existing accession contains unmanaged content or an unsupported previous output structure; choose a new output directory.")
    collection_name = accession_number if collection_name is None else collection_name
    _safe_component(collection_name)
    timestamp = _now()
    status = dict(schema_version=2, collection_name=collection_name, revision=1, accession_number=accession_number,
                  accession_path=accession_number, created_at=timestamp,
                  updated_at=timestamp, layout=layout, steps={})
    for stage in STAGE_IDS:
        status["steps"][stage] = dict(
            state="not_started", outcome=None, attempt=0, started_at=None,
            finished_at=None, freshness=dict(state="unverified", checked_at=None,
                                            method="none", reasons=[]),
            settings={}, inputs={}, outputs={}, evidence={}, result={})
    _validate(status, accession_number)
    documentation_dir(output_folder, accession_number)
    _write(path, status)
    return status


def load_status(output_folder, accession_number):
    """Load without creating or repairing anything; preserve unknown fields."""
    path = _status_path(output_folder, accession_number)
    if path.exists() and not is_managed_documentation(path.parent):
        raise StatusValidationError("Processing status is not inside managed accession documentation; original content was left unchanged")
    if not path.exists() and path.parent.parent.exists():
        entries = path.parent.parent.iterdir()
        if any(not is_managed_documentation(entry) for entry in entries):
            raise UnsupportedSchemaError("Accession has no current processing status and contains unmanaged or unsupported output. Original content was left unchanged.")
    try:
        with path.open(encoding="utf-8") as stream:
            status = json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StatusValidationError(f"Malformed status JSON in {path}: {exc}") from exc
    _validate(status, accession_number)
    collection_directory(output_folder, accession_number)
    return status


def save_status(output_folder, accession_number, status):
    """Save an existing record and return its new revision without mutating input.

    Refuse stale revisions and invalid existing files. Unknown fields loaded by
    callers survive because the entire supplied record is written.
    """
    path = _status_path(output_folder, accession_number)
    _validate(status, accession_number)
    previous = load_status(output_folder, accession_number)
    if status["revision"] != previous["revision"]:
        raise StatusValidationError("Revision does not match the stored status; reload before saving")
    candidate = deepcopy(status)
    candidate["revision"] += 1
    candidate["updated_at"] = _now()
    _write(path, candidate)
    return candidate


# ============================================================================
# User-facing status presentation
# ============================================================================

STEP_STAGES = {
    "ingest": ("antivirus", "ingest"),
    "format_identification": ("fits",),
    "reports": ("reports", "summary"),
    "fixity": ("fixity",),
    "bagging": ("bag_construct", "bag_validate", "tar_serialize"),
}
STAGE_NAMES = {
    "antivirus": "Virus Scan", "ingest": "Accession Ingest",
    "fits": "Format Identification", "reports": "Metadata Reports",
    "summary": "Collection Summary", "fixity": "Fixity Verification",
    "bag_construct": "Bag Construction", "bag_validate": "Bag Validation",
    "tar_serialize": "TAR Serialization",
}
STATE_LABELS = {
    "not_started": "Not Started", "running": "Running / Possibly Interrupted",
    "completed": "Completed", "failed": "Failed", "interrupted": "Incomplete Previous Attempt",
    "unknown": "Unknown",
}
OUTCOME_LABELS = {
    "clean": "Clean", "detections": "Detections", "partial": "Partial Results",
    "unavailable": "Unavailable", "empty": "Empty", "generated": "Generated",
    "processed": "Detailed Results Unavailable", "identified": "Identified",
    "unidentified": "Unidentified", "passed": "Fixity Verified", "findings": "Fixity Issues Found",
    "constructed": "Constructed", "rejected": "Rejected", "valid": "Valid",
    "invalid": "Invalid", "indeterminate": "Indeterminate", "serialized": "Serialized",
    "error": "Error",
}


def stage_text(step):
    label = STATE_LABELS.get(step["state"], "Unknown")
    outcome = step.get("outcome")
    if outcome:
        label += " — " + OUTCOME_LABELS.get(outcome, outcome.replace("_", " "))
    return label


def _summarize_group(records):
    states = [record["state"] for record in records]
    if "running" in states:
        return "Running / Possibly Interrupted"
    if "failed" in states:
        return "Needs Attention" if "completed" in states else "Failed"
    if "interrupted" in states:
        return "Incomplete Previous Attempt"
    if all(state == "completed" for state in states):
        return "Completed"
    if "completed" in states:
        return "Partially Complete"
    if "unknown" in states:
        return "Unknown"
    return "Not Started"


def summarize_user_steps(status):
    """Summarize five groups, with detail for all nine stage records.

    Input is a validated schema-v1 record. Optional operations are not assumed
    requested because a current GUI checkbox happens to be selected.
    """
    steps = status["steps"]
    summaries = {}
    for user_step, stages in STEP_STAGES.items():
        records = [steps[stage] for stage in stages]
        summaries[user_step] = dict(
            label=_summarize_group(records),
            detail="\n".join(f"{STAGE_NAMES[stage]}: {stage_text(steps[stage])}" for stage in stages))

    av, ingest = steps["antivirus"], steps["ingest"]
    if ingest["state"] == "completed" and av["state"] not in ("running", "interrupted"):
        label = "Completed"
        if av["state"] == "not_started":
            label += " — Virus Scan Not Run"
        elif av["state"] in ("failed", "unknown"):
            label += " — Virus Scan Needs Attention"
        elif av.get("outcome") in ("detections", "partial", "unavailable"):
            label += " — Virus Scan " + OUTCOME_LABELS[av["outcome"]]
        summaries["ingest"]["label"] = label
    elif av["state"] == "completed" and ingest["state"] == "not_started":
        summaries["ingest"]["label"] = "Partially Complete"

    for user_step, stage in (("format_identification", "fits"), ("fixity", "fixity")):
        summaries[user_step]["label"] = stage_text(steps[stage])
    fits = steps["fits"]
    if (fits["state"] == "completed" and fits.get("outcome") == "processed"
            and fits["freshness"]["state"] != "stale"):
        summaries["format_identification"]["label"] = "Completed — Format Identification Finished"
    if (steps["reports"]["state"] == "completed" and steps["reports"].get("outcome") == "partial"
            and summaries["reports"]["label"] == "Completed"):
        summaries["reports"]["label"] = "Needs Attention — Partial Reports"

    construction, validation, tar = (steps[stage] for stage in STEP_STAGES["bagging"])
    bag = summaries["bagging"]
    states = [record["state"] for record in (construction, validation, tar)]
    if "running" in states or "interrupted" in states or "failed" in states:
        pass  # Keep the conservative execution-state summary above.
    elif validation["state"] == "completed" and validation.get("outcome") == "invalid":
        bag["label"] = "Needs Attention — Bag Invalid"
    elif "unknown" in states:
        bag["label"] = "Partially Complete — Unknown History" if "completed" in states else "Unknown"
    elif validation["state"] == "completed" and validation.get("outcome") not in ("valid", "invalid"):
        bag["label"] = "Needs Attention — Validation Result Unclear"
    elif construction["state"] == "completed" or validation["state"] == "completed" or tar["state"] == "completed":
        bag["label"] = ("Completed" if all(state == "completed" for state in states) else
                        "TAR Serialized" if tar["state"] == "completed" else
                        "Bag Validated" if validation["state"] == "completed" else "Construction Completed")
        # These keys are honored only if explicitly present in recorded settings.
        # Current recorder does not yet persist optional-action request intent.
        settings = construction.get("settings", {})
        unfinished = []
        if settings.get("validate") is True and validation["state"] == "not_started":
            unfinished.append("Validation Pending")
        if (settings.get("serialize_tar") is True and settings.get("profile") == "aptrust"
                and tar["state"] == "not_started"):
            unfinished.append("TAR Pending")
        if unfinished:
            bag["label"] = "Partially Complete — " + "; ".join(unfinished)
    for user_step, stages in STEP_STAGES.items():
        stale = [stage for stage in stages if steps[stage]["freshness"]["state"] == "stale"]
        if stale:
            summaries[user_step]["label"] += " — Stale"
            summaries[user_step]["detail"] += "\nFreshness: " + "; ".join(
                f"{STAGE_NAMES[stage]}: {', '.join(steps[stage]['freshness']['reasons'])}" for stage in stale)
    return summaries


def format_stage_details(status):
    """Readable execution details; unverified freshness is not a failure."""
    lines = [f"Accession: {status['accession_number']}", f"Revision: {status['revision']}",
             f"Recorded layout: {status['layout']}", ""]
    for stages in STEP_STAGES.values():
        for stage in stages:
            record = status["steps"][stage]
            lines.append(f"{STAGE_NAMES[stage]}: {stage_text(record)}")
            lines.append(f"  Attempt: {record['attempt']}; freshness: {record['freshness']['state']}")
            if record["freshness"].get("reasons"):
                lines.append("  Freshness reasons: " + ", ".join(record["freshness"]["reasons"]))
            if record.get("started_at"):
                lines.append(f"  Started: {record['started_at']}")
            if record.get("finished_at"):
                lines.append(f"  Finished: {record['finished_at']}")
            if record.get("message"):
                lines.append(f"  Message: {record['message']}")
            for name, path in record.get("outputs", {}).items():
                lines.append(f"  Output {name}: {path}")
            lines.append("")
    return "\n".join(lines)


# ============================================================================
# Change-detection evidence and reconciliation
# ============================================================================

METHOD = "fingerprint-sha256-v1"
CHECKSUM_WORKFLOW = "sha256-v1"
CHECKSUM_STAGES = {"ingest", "reports", "summary", "fixity", "bag_construct", "bag_validate", "tar_serialize"}
DA = "http://dataaccessioner.org/schema/dda-1-1"
PREMIS = "info:lc/xmlns/premis-v2"
FITS = "http://hul.harvard.edu/ois/xml/ns/fits/fits_output"


def _fingerprint_hasher(algorithm, data=b""):
    if algorithm == "sha256":
        return hashlib.sha256(data)
    raise ValueError("unsupported_fingerprint_algorithm")


def _digest(value, algorithm="sha256"):
    return _fingerprint_hasher(algorithm, json.dumps(value, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")).hexdigest()


def file_fingerprint(path, algorithm="sha256"):
    path = Path(path)
    before = path.stat()
    digest = _fingerprint_hasher(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("artifact_changed_during_read")
    return digest.hexdigest()


def _node(element):
    return [element.tag, sorted(element.attrib.items()), (element.text or "").strip(),
            [_node(child) for child in element if isinstance(child.tag, str)]]


def _xml(path):
    tree = ET.parse(str(path), ET.XMLParser(resolve_entities=False, no_network=True))
    if tree.getroot().tag != f"{{{DA}}}collection":
        raise ValueError("invalid_accession_xml")
    files = tree.findall(f".//{{{DA}}}file")
    names = [record.get("name", "") for record in files]
    if len(set(names)) != len(names) or any(not name for name in names):
        raise ValueError("invalid_inventory_membership")
    return tree, sorted(files, key=lambda element: element.get("name"))


def inventory_fingerprint(path, algorithm="sha256"):
    tree, files = _xml(path)
    records = []
    for file in files:
        records.append(dict(path=file.get("name"), size=file.get("size"), md5=file.get("MD5"),
                            identifiers=[_node(n) for n in file.findall(f".//{{{PREMIS}}}objectIdentifier")],
                            fixity=[_node(n) for n in file.findall(f".//{{{PREMIS}}}fixity")],
                            premis_size=[n.text for n in file.findall(f".//{{{PREMIS}}}objectCharacteristics/{{{PREMIS}}}size")]))
        if "SHA256" in file.attrib:
            records[-1]["sha256"] = file.get("SHA256")
    return _digest(dict(accessions=[n.get("number") for n in tree.findall(f"{{{DA}}}accession")], files=records), algorithm)


def fits_fingerprint(path, algorithm="sha256"):
    _, files = _xml(path)
    records = []
    for file in files:
        embedded = file.findall(f".//{{{FITS}}}fits")
        values = {text for report in embedded for node in report.iter() for text in
                  [node.text, *node.attrib.values()] if text and text.strip()}
        formats = []
        for format in file.findall(f".//{{{PREMIS}}}format"):
            notes = " ".join(format.itertext()).lower()
            matching = any((node.text or "").strip() in values for node in format.iter())
            if "fits" in notes or "droid" in notes or matching:
                formats.append(_node(format))
        records.append(dict(path=file.get("name"), formats=formats, embedded=[_node(n) for n in embedded]))
    return _digest(records, algorithm)


def _no_link(path):
    if path.is_symlink() or path.is_junction():
        raise ValueError("payload_links_not_supported")


def resolve_payload_root(payload, layout):
    """Resolve logical accession files for inspection and downstream execution."""
    payload = Path(payload)
    _no_link(payload)
    if not payload.is_dir():
        raise FileNotFoundError(payload)
    names = {p.name.casefold() for p in payload.iterdir()}
    basic = ((payload / "data").is_dir() and (payload / "bagit.txt").is_file()
             and (payload / "bag-info.txt").is_file()
             and any(p.is_file() for p in payload.glob("manifest-*.txt")))
    indicators = bool(names & {"data", "bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"}) or any(
        re.fullmatch(r"(?:tag)?manifest-.*\.txt", name) for name in names)
    if layout == "ambiguous" or (indicators and not basic) or (layout == "bagged" and not basic):
        raise ValueError("ambiguous_payload_layout")
    root = payload / "data" if basic else payload
    _no_link(root)
    return root


def _membership(root, include_dirs=False):
    result = []
    _no_link(root)
    for directory, directories, files in collection_walk(root):
        for name in sorted(directories + files):
            path = Path(directory) / name
            _no_link(path)
            relative = path.relative_to(root).as_posix()
            if path.is_file():
                stat = path.stat()
                result.append([relative, "file", stat.st_size, stat.st_mtime_ns])
            elif path.is_dir():
                if include_dirs:
                    result.append([relative, "dir"])
            else:
                raise ValueError("unsupported_payload_entry")
    return sorted(result)


def payload_stat_fingerprint(payload, layout, algorithm="sha256"):
    return _digest(_membership(resolve_payload_root(payload, layout)), algorithm)


def bag_stat_fingerprint(bag, algorithm="sha256"):
    bag = Path(bag)
    if resolve_payload_root(bag, "bagged") != bag / "data":
        raise ValueError("ambiguous_payload_layout")
    critical = {}
    for path in sorted(bag.iterdir()):
        if path.name.casefold() in {"bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"} or re.fullmatch(r"(?:tag)?manifest-.*\.txt", path.name.casefold()):
            _no_link(path)
            critical[path.name] = file_fingerprint(path, algorithm)
    return _digest(dict(membership=_membership(bag, include_dirs=True), metadata=critical), algorithm)


def file_stat(path):
    stat = Path(path).stat()
    return dict(size=stat.st_size, mtime_ns=stat.st_mtime_ns)


def _specs(stage, status, accession, input_side, output):
    record = status["steps"][stage]
    xml = document_path(output, accession, "ingest", "xml", f"{accession}.xml", status).relative_to(output).as_posix()
    payload = collection_directory(output, accession).relative_to(output).as_posix()
    def descriptor(method, path, reason, scope="output"):
        return dict(method=method, path=path, scope=scope, reason=reason)
    inventory = descriptor("inventory-sha256-v1", xml, "baseline_inventory_changed")
    logical = descriptor("payload-stat-sha256-v1", payload, "payload_changed")
    exact_xml = descriptor("file-sha256-v1", xml, "xml_changed")
    bag = descriptor("bag-stat-sha256-v1", payload, "bag_changed")
    inputs = {
        "antivirus": {}, "ingest": {}, "fits": dict(inventory=inventory, payload=logical,
            profile=descriptor("file-sha256-v1", "fits/config/fits-droid.xml", "fits_profile_changed", "processing")),
        "reports": dict(xml=exact_xml, csv_stylesheet=descriptor("file-sha256-v1", "files.csv.xslt", "csv_stylesheet_changed", "stylesheets"),
                        html_stylesheet=descriptor("file-sha256-v1", "files.html.xslt", "html_stylesheet_changed", "stylesheets"),
                        payload=logical),
        "summary": dict(csv=descriptor("file-sha256-v1", document_path(output, accession, "reports", "csv", f"{accession}_files.csv", status).relative_to(output).as_posix(), "csv_changed"),
                        xml=exact_xml, csv_stylesheet=descriptor("file-sha256-v1", "files.csv.xslt", "csv_stylesheet_changed", "stylesheets"), payload=logical),
        "fixity": dict(inventory=inventory, payload=logical),
        "bag_construct": dict(inventory=inventory, payload=logical),
        "bag_validate": dict(bag=bag), "tar_serialize": dict(bag=bag),
    }
    if stage == "bag_validate":
        inputs[stage]["bag"] = dict(bag, reason="bag_changed_since_validation")
    if stage == "tar_serialize":
        inputs[stage]["bag"] = dict(bag, reason="bag_changed_since_serialization")
    if input_side:
        return inputs[stage]
    outputs = record["outputs"]
    evidence = {
        "antivirus": {name: descriptor("file-sha256-v1", path, f"{name}_output_changed") for name, path in outputs.items()},
        "ingest": dict(inventory=inventory, payload=logical),
        "fits": dict(fits=descriptor("fits-sha256-v1", xml, "fits_enrichment_changed")),
        "reports": {name: descriptor("file-sha256-v1", outputs.get(name), f"{name}_output_changed") for name in ("csv", "html")},
        "summary": dict(text=descriptor("file-sha256-v1", outputs.get("text"), "summary_output_changed")),
        "fixity": {name: descriptor("file-sha256-v1", outputs.get(name), f"fixity_{name}_changed") for name in ("csv", "log")},
        "bag_construct": dict(bag=bag), "bag_validate": {},
        "tar_serialize": dict(tar=descriptor("file-stat-v1", outputs.get("tar"), "tar_changed")),
    }
    return evidence[stage]


def _snapshot(descriptor, output, layout, stylesheets):
    value = descriptor["path"]
    if not isinstance(value, str) or not value or Path(value).is_absolute() or "\\" in value or ":" in value:
        raise ValueError("invalid_evidence_path")
    root = (stylesheets if descriptor["scope"] == "stylesheets" else
            Path(__file__).resolve().parent if descriptor["scope"] == "processing" else output)
    path = root / value
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("invalid_evidence_path")
    _no_link(path)
    recorded_method = descriptor["method"]
    method = recorded_method
    functions = {"file-sha256-v1": file_fingerprint, "inventory-sha256-v1": inventory_fingerprint, "fits-sha256-v1": fits_fingerprint,
                 "bag-stat-sha256-v1": bag_stat_fingerprint, "file-stat-v1": file_stat}
    if method == "file-stat-v1":
        digest = file_stat(path)
    elif method == "payload-stat-sha256-v1":
        digest = payload_stat_fingerprint(path, layout)
    else:
        digest = functions[method](path)
    return dict(method=recorded_method, value=digest, path=value, scope=descriptor["scope"])


def capture_stage(stage, status, output, accession, input_side, stylesheets=None):
    """Best-effort evidence capture; errors never invalidate technical completion."""
    output = Path(output).resolve()
    stylesheets = Path(stylesheets or XSLT_DIR).resolve()
    captured, errors = {}, []
    specs = _specs(stage, status, accession, input_side, output=output)
    for name, descriptor in specs.items():
        if stage == "bag_construct" and input_side and name == "inventory" and not (output / descriptor["path"]).exists():
            continue  # Construction without an XML baseline is an established API path.
        try:
            captured[name] = _snapshot(descriptor, output, status["layout"], stylesheets)
        except Exception:
            errors.append(f"evidence_capture_unavailable_{name}")
    if input_side:
        captured["settings"] = deepcopy(status["steps"][stage]["settings"])
    return captured, errors


def apply_execution_evidence(stage, candidate, output, accession, captured_inputs, input_errors):
    record = candidate["steps"][stage]
    evidence, errors = capture_stage(stage, candidate, output, accession, input_side=False)
    record["inputs"], record["evidence"] = captured_inputs, evidence
    reasons = sorted(set(input_errors + errors))
    if stage == "antivirus":
        reasons.append("time_sensitive_scan")
    record["freshness"].update(state="unverified" if reasons else "current", checked_at=record["finished_at"],
                               method=METHOD, reasons=reasons)


def reconcile_status(status, output, accession, stylesheets=None):
    """Return a copy with freshness updates only. No historical evidence is created."""
    _validate(status, accession)
    output = Path(output).resolve()
    _status_path(output, accession)
    stylesheets = Path(stylesheets or XSLT_DIR).resolve()
    candidate = deepcopy(status)
    cache = {}
    for stage, record in candidate["steps"].items():
        if stage not in STAGE_IDS or record["state"] != "completed":
            continue
        stale, unknown = [], []
        if stage in CHECKSUM_STAGES and record["settings"].get("checksum_workflow") != CHECKSUM_WORKFLOW:
            record["freshness"].update(state="stale", checked_at=now(), method=METHOD,
                                       reasons=["checksum_workflow_changed"])
            continue
        has_evidence = bool(record["inputs"] or record["evidence"])
        if not has_evidence:
            if record["freshness"]["state"] == "current":
                record["freshness"].update(state="unverified", method=METHOD, reasons=["missing_evidence"])
            continue  # Pre-fingerprint history is not retrospectively verified.
        for side in ("inputs", "evidence"):
            specs = _specs(stage, candidate, accession, side == "inputs", output=output)
            if stage == "bag_construct" and "inventory" not in record["inputs"]:
                specs.pop("inventory", None)
            for name, descriptor in specs.items():
                previous = record[side].get(name)
                if not isinstance(previous, dict) or not {"method", "value", "path", "scope"} <= previous.keys():
                    unknown.append("missing_evidence")
                    continue
                if previous.get("method") != descriptor["method"]:
                    unknown.append("unsupported_evidence_method")
                    continue
                try:
                    key = (descriptor["method"], descriptor["scope"], descriptor["path"])
                    if key not in cache:
                        cache[key] = _snapshot(descriptor, output, candidate["layout"], stylesheets)
                    current = cache[key]
                    if previous != current:
                        stale.append(descriptor["reason"])
                except FileNotFoundError:
                    stale.append("missing_output" if side == "evidence" else "missing_input")
                    stale.append(descriptor["reason"])
                except (OSError, ValueError, TypeError, ET.XMLSyntaxError, KeyError) as exc:
                    if str(exc) in ("ambiguous_payload_layout", "invalid_inventory_membership", "invalid_accession_xml", "payload_links_not_supported", "unsupported_payload_entry"):
                        stale.append(str(exc))
                    else:
                        unknown.append("fingerprint_unavailable")
        if "settings" in record["inputs"] and record["inputs"]["settings"] != record["settings"]:
            stale.append("settings_changed")
        if stage == "antivirus":
            unknown.append("time_sensitive_scan")
        if any(reason.startswith("evidence_capture_unavailable") for reason in record["freshness"]["reasons"]):
            unknown.append("missing_evidence")
        state = "stale" if stale else "unverified" if unknown else "current"
        reasons = sorted(set(stale + unknown))
        fresh = record["freshness"]
        if (fresh["state"], fresh["method"], fresh["reasons"]) != (state, METHOD, reasons):
            fresh.update(state=state, method=METHOD, reasons=reasons)
    _invalidate_dependencies(candidate)
    for stage in STAGE_IDS:
        before, after = status["steps"][stage]["freshness"], candidate["steps"][stage]["freshness"]
        if any(before[key] != after[key] for key in ("state", "method", "reasons")):
            after["checked_at"] = datetime.now(timezone.utc).isoformat()
    return candidate


def _invalidate_dependencies(status):
    """Propagate known upstream changes only where consumer lineage is insufficient.

    New Reports/Summary capture lineage themselves, so re-generated work that
    matches current inputs is not poisoned by an older upstream stale record.
    """
    dependencies = {
        "ingest": (("fits", "inventory"), ("reports", "xml"), ("summary", "xml"), ("fixity", "inventory"), ("bag_construct", "inventory")),
        "fits": (("reports", "xml"), ("summary", "xml")),
        "reports": (("summary", "csv"),),
        "bag_construct": (("bag_validate", "bag"), ("tar_serialize", "bag")),
    }
    for source, targets in dependencies.items():
        origin = status["steps"][source]
        if origin["freshness"]["state"] != "stale":
            continue
        causes = origin["freshness"]["reasons"]
        if source == "reports" and not any(c in causes for c in ("xml_changed", "csv_output_changed", "csv_stylesheet_changed", "payload_changed", "baseline_inventory_changed", "fits_enrichment_changed")):
            continue  # HTML-only modifications are not Summary dependencies.
        if source == "ingest" and not any(c in causes for c in ("baseline_inventory_changed", "payload_changed", "missing_output", "ambiguous_payload_layout")):
            continue
        for target, lineage in targets:
            record = status["steps"][target]
            if record["state"] != "completed" or (record["freshness"]["state"] == "current" and lineage in record["inputs"]):
                continue
            reason = f"upstream_{source}_changed"
            if reason not in record["freshness"]["reasons"]:
                record["freshness"].update(state="stale", method=METHOD,
                                           reasons=sorted(set(record["freshness"]["reasons"] + [reason])))


def load_reconciled_status(output, accession, stylesheets=None):
    status = load_status(output, accession)
    candidate = reconcile_status(status, output, accession, stylesheets)
    return save_status(output, accession, candidate) if candidate != status else status


# ============================================================================
# Execution-boundary recording
# ============================================================================

class StatusRecordingError(RuntimeError):
    """Execution history could not be reliably persisted."""


def now():
    return datetime.now(timezone.utc).isoformat()


class RunRecorder:
    """One serialized managed run. Never consult stage states to skip work."""
    def __init__(self, output, accession, collection_name=None):
        self.output = Path(output).resolve()
        self.accession = accession
        try:
            self.status = load_status(self.output, accession)
        except FileNotFoundError:
            # Existing artifacts do not establish layout or execution history.
            self.status = create_status(self.output, accession, layout="unknown", collection_name=collection_name)

    def paths(self, **paths):
        """Record only actual artifacts, relative to the output root."""
        outputs = {}
        for name, path in paths.items():
            if path is None or not isinstance(path, (str, Path)):
                continue
            path = Path(path)
            if path.exists():
                outputs[name] = path.resolve().relative_to(self.output).as_posix()
        return outputs

    def run(self, stage, operation, normalize, *, settings=None, failure_outcome="error",
            progress=None, layout=None):
        settings = dict(settings or {})
        if stage in CHECKSUM_STAGES:
            settings["checksum_workflow"] = CHECKSUM_WORKFLOW
        candidate = deepcopy(self.status)
        step = candidate["steps"][stage]
        step.update(state="running", outcome=None, attempt=step["attempt"] + 1,
                    started_at=now(), finished_at=None, settings=settings or {},
                    inputs={}, outputs={}, evidence={}, result={})
        step.pop("message", None)
        # Only this attempted stage is reset; downstream records stay unchanged.
        step["freshness"].update(state="unverified", checked_at=None, method="none", reasons=[])
        try:
            self.status = save_status(self.output, self.accession, candidate)
        except Exception as exc:
            raise StatusRecordingError(f"Cannot record {stage} running; operation was not started: {exc}") from exc
        captured_inputs, input_errors = capture_stage(stage, self.status, self.output, self.accession, input_side=True)
        try:
            value = operation()
        except Exception as operation_error:
            candidate = deepcopy(self.status)
            candidate["steps"][stage].update(
                state="failed", outcome=failure_outcome(operation_error) if callable(failure_outcome) else failure_outcome, finished_at=now(),
                message=str(operation_error)[:2000], result=deepcopy(progress or {}))
            if stage == "reports" and (progress or {}).get("csv_generated"):
                candidate["steps"][stage]["outcome"] = "partial"
                candidate["steps"][stage]["outputs"] = self.paths(csv=progress.get("csv_path") or document_path(self.output, self.accession, "reports", "csv", f"{self.accession}_files.csv"))
            if stage == "bag_construct":
                candidate["layout"] = "unknown"  # Rejected/partial construction is not a verified layout.
            try:
                self.status = save_status(self.output, self.accession, candidate)
            except Exception as save_error:
                raise StatusRecordingError(
                    f"{stage} failed: {operation_error}. Failure status could not be saved: {save_error}; "
                    "the stored attempt may remain running.") from operation_error
            raise
        # A normalization/final-write failure must leave the durable running boundary.
        try:
            result = normalize(value)
            candidate = deepcopy(self.status)
            disposition = dict(state="completed", finished_at=now())
            disposition.update(result)
            candidate["steps"][stage].update(disposition)
            if layout and candidate["steps"][stage]["state"] == "completed":
                candidate["layout"] = layout
            if candidate["steps"][stage]["state"] == "completed":
                apply_execution_evidence(stage, candidate, self.output, self.accession, captured_inputs, input_errors)
            self.status = save_status(self.output, self.accession, candidate)
        except Exception as exc:
            raise StatusRecordingError(
                f"{stage} returned, but its final status could not be recorded: {exc}. "
                "Artifacts are retained; the stored attempt may remain running.") from exc
        return value


def file_count(xml):
    try:
        tree = ET.parse(str(xml), ET.XMLParser(resolve_entities=False, no_network=True))
        return len(tree.findall(".//{http://dataaccessioner.org/schema/dda-1-1}file"))
    except (OSError, ET.XMLSyntaxError):
        return None


def fixity_result(recorder, returned):
    csv_path, log_path = returned if isinstance(returned, tuple) and len(returned) == 2 else (None, None)
    counts = {"ok_count": None, "mismatch_count": None, "missing_count": None, "error_count": None}
    outcome = "processed"
    try:
        with Path(csv_path).open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if "status" not in (reader.fieldnames or []):
                raise ValueError("Missing status column")
            statuses = [row["status"] for row in reader]
        if any(status not in {"OK", "MISMATCH", "MISSING", "ERROR"} for status in statuses):
            raise ValueError("Unknown fixity finding")
        counts = dict(zip(counts, (statuses.count(s) for s in ("OK", "MISMATCH", "MISSING", "ERROR"))))
        outcome = "empty" if not statuses else "passed" if all(s == "OK" for s in statuses) else "findings"
    except (OSError, TypeError, ValueError, csv.Error):
        pass  # Do not turn unavailable counts into zero or invent a pass.
    return dict(outcome=outcome, result=counts, outputs=recorder.paths(csv=csv_path, log=log_path))


# ============================================================================
# Read-only resume planning
# ============================================================================

SAFE_RERUN = {"antivirus", "fits", "reports", "summary", "fixity", "bag_validate", "tar_serialize"}
ACCEPTABLE = {
    "antivirus": {"clean", "empty"}, "ingest": {"generated", "empty"},
    "fits": {"identified", "unidentified", "processed", "empty"},
    "reports": {"generated"}, "summary": {"generated", "empty"},
    "fixity": {"passed"}, "bag_construct": {"constructed"},
    "bag_validate": {"valid"}, "tar_serialize": {"serialized"},
}


def bag_layout(payload):
    payload = Path(payload)
    if not payload.is_dir():
        return "missing"
    indicators = [p for p in payload.iterdir() if p.name.casefold() in
                  {"data", "bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"}
                  or re.fullmatch(r"(?:tag)?manifest-.*\.txt", p.name.casefold())]
    if not indicators:
        return "unbagged"
    if ((payload / "data").is_dir() and (payload / "bagit.txt").is_file()
            and (payload / "bag-info.txt").is_file()
            and any(p.is_file() for p in payload.glob("manifest-*.txt"))):
        return "bagged"
    return "ambiguous"


def artifact_availability(output, accession, status=None):
    """No hashing, timestamps, XML parsing, or writes. Reject escaping recorded paths."""
    root = Path(output).resolve()
    _status_path(root, accession)  # Shared accession-component safety rules.
    payload = collection_directory(root, accession)
    xml = document_path(root, accession, "ingest", "xml", f"{accession}.xml", status)
    csv = document_path(root, accession, "reports", "csv", f"{accession}_files.csv", status)
    layout = bag_layout(payload)
    recorded = {}
    requirements = {
        "antivirus": {"csv": "file", "log": "file"},
        "ingest": {"payload": "dir", "xml": "file"}, "fits": {"xml": "file"},
        "reports": {"csv": "file", "html": "file"}, "summary": {"text": "file"},
        "fixity": {"csv": "file", "log": "file"}, "bag_construct": {"bag": "dir"},
        "bag_validate": {}, "tar_serialize": {"tar": "file"},
    }
    for stage, required in requirements.items():
        outputs = status["steps"][stage]["outputs"] if status else {}
        valid = True
        for name, kind in required.items():
            value = outputs.get(name)
            if not isinstance(value, str) or not value or Path(value).is_absolute() or "\\" in value or ":" in value:
                valid = False
                break
            path = root / value
            if not path.resolve().is_relative_to(root) or not (path.is_dir() if kind == "dir" else path.is_file()):
                valid = False
                break
            expected = {("ingest", "payload"): payload, ("ingest", "xml"): xml,
                        ("fits", "xml"): xml, ("bag_construct", "bag"): payload}.get((stage, name))
            if expected is not None and path.resolve() != expected.resolve():
                valid = False
                break
        recorded[stage] = valid
    return dict(payload=payload.is_dir(), xml=xml.is_file(),
                csv=csv.is_file(), layout=layout,
                bag=layout == "bagged", bag_profile="aptrust" if (payload / "aptrust-info.txt").is_file() else "generic",
                recorded=recorded)


def build_resume_plan(status, selected_steps, sub_options, output, accession, artifacts=None):
    """Return nine ordered stage decisions without mutating history or selections.

    Review pauses the whole requested plan. Resolve by changing requested work,
    explicit safe rerun, or external review; running records never auto-rerun.
    """
    if status is not None:
        _validate(status, accession)
    available = artifact_availability(output, accession, status) if artifacts is None else artifacts
    requested = {
        "antivirus": selected_steps.get("ingest", False) and sub_options.get("antivirus", False),
        "ingest": selected_steps.get("ingest", False), "fits": selected_steps.get("fits", False),
        "reports": selected_steps.get("reports", False), "summary": selected_steps.get("reports", False),
        "fixity": selected_steps.get("fixity", False), "bag_construct": selected_steps.get("bagging", False),
        "bag_validate": selected_steps.get("bagging", False) and sub_options.get("validate", False),
        "tar_serialize": selected_steps.get("bagging", False) and sub_options.get("tar", False)
                         and sub_options.get("profile") == "aptrust",
    }
    confirmed_stale = sub_options.get("confirmed_stale", False)
    rerun = sub_options.get("rerun_completed", False)
    decisions = {}
    for stage in STAGE_IDS:
        action, reason = "skip", "not_requested"
        record = status["steps"][stage] if status else None
        if requested[stage]:
            action, reason = "run", "no_managed_status" if record is None else record["state"]
            if record is not None:
                state, outcome = record["state"], record["outcome"]
                if state in ("running", "unknown"):
                    action, reason = "review", "previous_attempt_may_be_interrupted" if state == "running" else "unknown_history"
                elif stage in ("ingest", "bag_construct") and state in ("failed", "interrupted"):
                    action, reason = "review", "unsafe_automatic_retry"
                elif state == "completed":
                    if rerun and stage in SAFE_RERUN:
                        action, reason = "run", "explicit_safe_rerun"
                    elif record["freshness"]["state"] == "stale":
                        action, reason = ("run" if stage in SAFE_RERUN else "review"), "recorded_stale"
                    elif outcome not in ACCEPTABLE[stage]:
                        action, reason = "review", "outcome_not_satisfied"
                    elif available["recorded"][stage] and (stage not in ("bag_construct", "bag_validate") or available["bag"]):
                        action, reason = "reuse", "completed_unverified" if record["freshness"]["state"] == "unverified" else "completed_outputs_present"
                    elif stage in ("ingest", "bag_construct"):
                        action, reason = "review", "completed_outputs_missing_or_ambiguous"
                    else:
                        action, reason = "run", "completed_outputs_missing"
            if (stage == "ingest" and record is not None and record["state"] == "completed"
                    and record["freshness"]["state"] == "stale" and confirmed_stale
                    and available["xml"] and available["payload"]):
                action, reason = "skip", "preserve_existing_accession"
            if stage == "antivirus" and action == "reuse":
                result = record["result"]
                if result.get("error_count") != 0 or result.get("detection_count") != 0 or result.get("scanned_count") is None:
                    action, reason = "review", "scan_result_not_usable"
            if stage == "bag_construct" and available["bag"] and action == "run":
                # Preserve selective validation/TAR against an unmanaged existing bag.
                action, reason = ("skip", "existing_bag_no_construction") if requested["bag_validate"] or requested["tar_serialize"] else ("block", "existing_bag_cannot_be_rebuilt")
            if stage == "bag_construct" and available["layout"] == "ambiguous":
                action, reason = "block", "ambiguous_bag_layout"
            if stage in ("bag_construct", "bag_validate", "tar_serialize") and available["bag"] and available["bag_profile"] != sub_options.get("profile"):
                action, reason = "review", "existing_bag_profile_mismatch"
        decisions[stage] = dict(stage=stage, action=action, reason=reason)
        if record is not None and record["freshness"]["state"] == "stale":
            decisions[stage]["freshness_reasons"] = list(record["freshness"]["reasons"])

    def dependency(stage, producer, available_now):
        current = decisions[stage]
        if current["action"] not in ("run", "reuse"):
            return
        upstream = decisions[producer]
        if upstream["action"] in ("review", "block"):
            current.update(action="block", reason=f"{producer}_requires_review")
        elif upstream["action"] == "run":
            current.update(action="run", reason=f"same_run_{producer}_output")
        elif current["action"] == "run" and not available_now:
            current.update(action="block", reason=f"missing_{producer}_prerequisite")

    for stage in ("fits", "reports", "fixity"):
        dependency(stage, "ingest", available["xml"] and (available["payload"] if stage != "reports" else True))
    dependency("reports", "fits", available["xml"] or decisions["ingest"]["action"] == "run")
    dependency("summary", "reports", available["csv"])
    for stage in ("fits", "fixity"):
        if decisions[stage]["action"] == "run" and decisions["ingest"]["action"] != "run" and available["layout"] not in ("unbagged", "bagged"):
            decisions[stage].update(action="block", reason="unbagged_payload_required")
    if decisions["ingest"]["action"] == "run" and status and (available["xml"] or available["bag"]):
        decisions["ingest"].update(action="review", reason="existing_preservation_baseline")
    if decisions["ingest"]["action"] == "run" and decisions["antivirus"]["action"] == "reuse":
        decisions["antivirus"].update(action="review", reason="scan_cannot_be_reused_for_new_ingest")
    dependency("bag_construct", "ingest", available["payload"])
    for stage in ("bag_validate", "tar_serialize"):
        dependency(stage, "bag_construct", available["bag"])
    if requested["tar_serialize"] and requested["bag_validate"]:
        if decisions["bag_validate"]["action"] in ("review", "block"):
            decisions["tar_serialize"].update(action="block", reason="successful_validation_required")
    if status and requested["bag_construct"] and status["steps"]["fixity"]["outcome"] == "findings":
        if decisions["fixity"]["action"] != "run":
            decisions["bag_construct"].update(action="block", reason="managed_fixity_findings_require_passing_rerun")
        else:
            decisions["bag_construct"]["requires_passing_fixity"] = True
    # Propagate late safety decisions to dependent actions in the preview.
    for stage, producer in (("fits", "ingest"), ("reports", "ingest"), ("fixity", "ingest"),
                            ("reports", "fits"), ("summary", "reports"), ("bag_construct", "ingest"),
                            ("bag_validate", "bag_construct"), ("tar_serialize", "bag_construct")):
        if decisions[stage]["action"] in ("run", "reuse") and decisions[producer]["action"] in ("review", "block"):
            decisions[stage].update(action="block", reason=f"{producer}_requires_review")
    if requested["tar_serialize"] and requested["bag_validate"] and decisions["bag_validate"]["action"] in ("review", "block"):
        decisions["tar_serialize"].update(action="block", reason="successful_validation_required")
    return list(decisions.values())


def format_execution_plan(plan):
    by_stage = {decision["stage"]: decision for decision in plan}
    headings = ("Ingest", "Format Identification", "Reports", "Fixity", "Bagging")
    lines = ["Execution Plan", ""]
    for heading, stages in zip(headings, STEP_STAGES.values()):
        entries = [by_stage[stage] for stage in stages]
        if all(entry["reason"] == "not_requested" for entry in entries):
            lines.append(f"{heading} — Not Selected")
        else:
            lines.append(f"{heading}:")
            for entry in entries:
                detail = entry['reason'].replace('_', ' ')
                if entry.get("freshness_reasons"):
                    detail += ": " + ", ".join(reason.replace("_", " ") for reason in entry["freshness_reasons"])
                lines.append(f"  {STAGE_NAMES[entry['stage']]} — {entry['action'].title()} ({detail})")
    lines.append("\nFreshness uses recorded change-detection evidence; it is not integrity verification.")
    return "\n".join(lines)
