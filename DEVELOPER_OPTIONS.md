# Archives Pipeline — Developer Options

Developers can customize or replace the tools the Archives Pipeline uses for file format identification, virus scanning, preservation packaging, and metadata reports.

## FITS / DROID

The pipeline uses the bundled FITS 1.6.0 with only DROID enabled in [`fits/config/fits-droid.xml`](fits/config/fits-droid.xml). To enable more tools, copy the active profile, add the desired `<tool>` entries from the bundled FITS configuration, and point `FITS_PROFILE` in `pipeline.py` to the new profile. Keep DROID enabled if you need PRONOM identifiers (PUIDs).

Test the modified profile on a small, representative accession. Check identification accuracy against known formats, verify the expected PUIDs, and compare processing time with the original profile. See the [FITS configuration guide](fits/FITS-configuration.md) for detailed instructions.

## Virus Scanning

The pipeline supports optional Microsoft Defender scanning on Windows. To integrate a different scanner, update `run_antivirus_scan()` in [`pipeline.py`](pipeline.py) and the scanner availability checks, controls, and result handling in [`GUI.py`](GUI.py). Other installed scanners require explicit integration.

## BagIt Packaging

The pipeline uses `bagit-python` to create and validate bags. Enable **BagIt Packaging** in the GUI, then choose **Generic BagIt** or **APTrust** under **BagIt Profile** in the **BagIt Metadata** panel.

To customize or replace packaging, start with `construct_bag()`, `validate_bag()`, and `serialize_bag_to_tar()` in [`pipeline.py`](pipeline.py). Update the options or stage handling in [`GUI.py`](GUI.py) if the integration changes. Preserve the accession checksum checks, the bag manifests and validation results, and the recorded status of construction, validation, and TAR serialization so users can resume processing.

## Metadata Reports

The pipeline uses XSLT to transform accession XML into CSV and HTML reports. Edit [`resources/xslt/files.csv.xslt`](resources/xslt/files.csv.xslt) or [`resources/xslt/files.html.xslt`](resources/xslt/files.html.xslt) to change report fields or formatting. If you change CSV columns, check that the text summary still works. To change how transformations run, update `run_xslt_processor()` in [`pipeline.py`](pipeline.py).

[Back to README](README.md) · [How to Use](HOW_TO_USE.md)
