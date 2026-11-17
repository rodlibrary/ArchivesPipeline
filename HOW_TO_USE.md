# Archives Pipeline — How to Use

The Archives Pipeline helps Library staff transfer files for an accession, document what it contains, check file integrity, and optionally create a preservation package.

[Get Started](#get-started) · [Process a New Accession](#process-a-new-accession) · [Resume an Existing Accession](#resume-an-existing-accession) · [Rerun Completed or Outdated Steps](#rerun-completed-or-outdated-steps) · [Review Your Results](#review-your-results)

---

## Get Started

Follow the [installation instructions](install/INSTALLATION.md). Open a terminal in the Archives Pipeline folder and run:

```sh
python GUI.py
```

---

## Process a New Accession

1. Set **Input Directory** to the folder containing the original files.
2. Set **Output Directory** to the parent folder where the application should save the accession and its reports.
3. Enter the **Accession Number** assigned to the collection. The application uses it to name the accession folder and associate it with its processing history.
4. Select the processing steps you want and click **Run Selected Steps**. You can run a subset now and finish the remaining steps later. Steps that need earlier results require those results to be available.

| Step | What it does |
| --- | --- |
| 1. Ingest (Data Accessioner) | Copies files into the accession folder, preserves the folder structure, and records file information and checksums in XML. |
| 2. Identify File Formats | Identifies file formats and adds technical information to the accession XML. |
| 3. Generate Metadata Reports | Creates CSV and HTML reports and a text summary from the accession metadata. |
| 4. Verify File Integrity | Checks accession files against their recorded checksums and reports mismatches and missing files. |
| 5. BagIt Packaging (optional) | Creates a preservation package for an unbagged accession. Select **Validate bag after creation** separately to check the bag. With the **APTrust** profile, select **Serialize to .tar (required for APTrust upload)** separately to create a TAR archive. |

During Ingest, you can select **Scan files with Microsoft Defender** to request a virus scan before transfer when Defender is available. Select **Move files instead of copy** if you want successfully transferred files removed from the input folder. Copying keeps the originals in place.

---

## Resume an Existing Accession

1. Reopen the application and enter the same **Output Directory** and **Accession Number** used for the original run. Use the parent output folder you previously selected.
2. Click **Load / Refresh Status**.
3. Review the status beside each step. Open **Status Details** to see recorded results and any items that need attention.
4. Select the unfinished steps and click **Run Selected Steps**. The application reuses previously completed work when its results are current and available.

---

## Rerun Completed or Outdated Steps

- **Stale** means the application detected a change that may make a previous result outdated. Check **Status Details** for the reason and follow the application's prompts to review or rerun the affected steps.
- Use **Rerun completed selected steps** when you deliberately want to repeat eligible completed work. Select the steps you want to repeat, then click **Run Selected Steps**. Leave **Ingest** unchecked when you are simply resuming an accession whose files have already been transferred.
- Investigate file-integrity problems using the fixity reports. Rerunning **Verify File Integrity** checks the files again. It does not repair damaged files or restore missing ones.
- **BagIt Packaging** is optional. After packaging, the application can validate the existing bag and create a TAR archive, but it blocks a new Ingest into the packaged accession and cannot rebuild the existing bag directly.

---

## Review Your Results

- **Accession XML** records file inventory and checksums and includes format information after identification.
- **Metadata CSV and HTML** provide a spreadsheet-friendly file list and a report you can open in a browser. The reports step also produces a text summary.
- **Fixity CSV and LOG** show the file-integrity check results.
- **Optional BagIt and TAR outputs** include the preservation package and a TAR archive if you selected serialization.

Use **Status Details** to review processing history and **View Error Details** to reopen the full message after a processing error.

[Back to README](README.md)
