# 03 – Analysis Pipeline

# Analysis Pipeline

## Purpose

The Analysis Pipeline is the core workflow of MICEPP Scanner.

It defines every operation performed on a piece of digital evidence, from the moment it is uploaded until a forensic report is generated and validated by a human expert.

The pipeline guarantees that every analysis is reproducible, traceable, and preserves the integrity of the original evidence.

---

# Pipeline Overview

The complete workflow is illustrated below.

```text
Evidence Upload
        │
        ▼
Integrity Verification
        │
        ▼
Original Evidence Storage
        │
        ▼
Working Copy Creation
        │
        ▼
Artifact Extraction
        │
        ▼
Static Analysis
        │
        ▼
Machine Learning
        │
        ▼
Dynamic Analysis (Optional)
        │
        ▼
Finding Normalization
        │
        ▼
Risk Consolidation
        │
        ▼
Human Review
        │
        ▼
PDF Report
        │
        ▼
Audit Verification
```

Each stage has a single responsibility and contributes to the final forensic assessment.

---

# Step 1 – Evidence Upload

The pipeline begins when an analyst uploads a file or forensic image.

Examples include:

* Executables
* Office documents
* PDF documents
* ZIP archives
* TAR archives
* RAW disk images
* E01 forensic images

At this stage, no analysis is performed.

The objective is only to securely receive the evidence.

---

# Step 2 – Integrity Verification

Immediately after upload, the platform calculates cryptographic hashes.

Generated values include:

* SHA-256
* SHA-1
* MD5

The evidence size is also recorded.

These values uniquely identify the evidence and become part of the forensic chain of custody.

---

# Step 3 – Original Evidence Preservation

The uploaded file is stored separately from future analysis outputs.

Important principles:

* Original evidence is immutable.
* It is never modified.
* It is never executed.
* It remains available for future verification.

Every subsequent operation works on a copy rather than on the original evidence.

---

# Step 4 – Working Copy Creation

A dedicated working copy is created.

This copy is isolated from the preserved evidence and is the only version manipulated during analysis.

This approach guarantees that the forensic evidence remains unchanged throughout the investigation.

---

# Step 5 – Artifact Extraction

If the uploaded file is an archive or forensic image, its contents are extracted into the working directory.

Examples include:

* ZIP archives
* TAR archives
* RAW images
* E01 images

Extraction is performed with safety controls to prevent archive traversal attacks and excessive extraction sizes.

---

# Step 6 – Static Analysis

The working copy is inspected using multiple specialized analyzers.

Typical analyses include:

* MIME type detection
* File entropy
* String extraction
* PE metadata inspection
* Office macro detection
* PDF active content inspection
* YARA rule matching
* ClamAV signature scanning

Each analyzer produces structured findings describing the observed characteristics.

Static analysis does not execute the uploaded file.

---

# Step 7 – Machine Learning Analysis

Feature vectors are extracted from the analyzed artifact.

If a trained model is available:

* Features are evaluated.
* Malware probability is estimated.
* Confidence values are produced.

If no trained model exists:

* The pipeline records that machine learning is unavailable.
* The remaining analyses continue normally.

The absence of an AI model never blocks the pipeline.

---

# Step 8 – Dynamic Analysis (Optional)

When a CAPE/Cuckoo sandbox is configured, the artifact may be submitted for execution inside an isolated environment.

Possible observations include:

* Process creation
* File system activity
* Registry modifications
* Network activity
* Persistence mechanisms

If no sandbox is configured:

* The pipeline explicitly reports that dynamic analysis is unavailable.
* No simulated or fabricated results are generated.

---

# Step 9 – Finding Normalization

Each analyzer returns results using its own internal format.

Before consolidation, all findings are converted into a common representation.

Each normalized finding typically contains:

* Category
* Severity
* Confidence
* Description
* Technical details
* Source analyzer

Normalization allows different analyzers to be compared consistently.

---

# Step 10 – Risk Consolidation

The pipeline aggregates all normalized findings.

Risk evaluation considers:

* Static analysis
* Machine learning
* Sandbox results (if available)

The resulting analysis includes:

* Overall score
* Automated verdict
* Coverage information
* Analysis completeness

The automated verdict assists analysts but does not replace expert judgement.

---

# Step 11 – Human Review

Every completed analysis enters a review stage.

An authorized reviewer may:

* Validate the analysis.
* Reject the analysis.
* Request additional investigation.
* Classify artifacts as benign or malicious.

Human validation is mandatory before the analysis becomes final.

---

# Step 12 – Report Generation

After review, a forensic PDF report is generated.

The report summarizes:

* Evidence metadata
* Integrity hashes
* Analysis findings
* Risk assessment
* Reviewer decision
* Audit information

The report serves as the official record of the completed analysis.

---

# Step 13 – Audit Chain

Every important operation performed during the pipeline generates an audit event.

Typical events include:

* Case creation
* Evidence ingestion
* Analysis queued
* Analysis started
* Analysis completed
* Report generated
* Review completed

Audit events are linked together using cryptographic HMAC chaining.

This mechanism allows later verification that the history has not been modified.

---

# Pipeline Design Principles

The pipeline follows several fundamental principles:

* Preserve original evidence.
* Never execute uploaded files on the application server.
* Separate orchestration from analysis engines.
* Normalize findings before scoring.
* Never fabricate unavailable results.
* Require human validation.
* Maintain complete traceability.

These principles ensure that analyses remain reproducible, transparent, and suitable for forensic workflows.

---

# Extension Points

The pipeline has been designed to accommodate future enhancements.

Potential additions include:

* VirusTotal integration
* MISP enrichment
* OpenCTI correlation
* Additional YARA rule sets
* Behavioral AI models
* MITRE ATT&CK mapping
* Sigma rule evaluation
* Threat intelligence enrichment

New capabilities should integrate into existing pipeline stages without altering the overall workflow.

---

# Pipeline Summary

The Analysis Pipeline is the operational backbone of MICEPP Scanner.

Rather than relying on a single detection engine, it orchestrates multiple independent analysis components, consolidates their observations, preserves forensic integrity, and presents the results for expert review.

Its modular design allows the platform to evolve while maintaining a consistent and auditable forensic process.
