# 03 – Database Architecture

# Database Architecture

## Purpose

The database is the persistent storage layer of MICEPP Scanner.

It stores all information required to manage forensic investigations, preserve evidence metadata, track analysis jobs, maintain audit records, manage users, and support machine learning.

Unlike uploaded files, which are stored on dedicated storage volumes, the database only stores metadata and relationships between forensic objects.

PostgreSQL is used as the primary relational database management system.

---

# Database Responsibilities

The database is responsible for storing:

* User accounts
* Authentication metadata
* Roles and permissions
* Investigation cases
* Evidence metadata
* Analysis jobs
* Analysis findings
* AI model metadata
* Generated reports
* Audit events

Large binary files are **not** stored inside the database.

Instead, the database keeps references to their storage locations together with integrity information.

---

# High-Level Entity Relationships

The platform revolves around a small number of core entities.

```text
User
 │
 ├──────────────┐
 │              │
 ▼              ▼
Case        AuditEvent
 │
 ▼
Evidence
 │
 ▼
AnalysisJob
 │
 ├──────────────┐
 ▼              ▼
Finding      Report
```

This hierarchy reflects the forensic workflow.

A case contains evidence.

Evidence produces analyses.

Analyses produce findings and reports.

Every important operation generates audit events.

---

# Core Entities

## User

### Purpose

Represents an authenticated platform user.

Users interact with the system according to their assigned role.

Typical roles include:

* Administrator
* Analyst
* Reviewer

### Responsibilities

* Authentication
* Authorization
* Ownership of actions
* Audit attribution

---

## Case

### Purpose

Represents a forensic investigation.

A case groups all evidence, analyses and reports related to a specific incident.

Typical information includes:

* Reference
* Title
* Description
* Creation date
* Status

A case acts as the root object of an investigation.

---

## Evidence

### Purpose

Represents uploaded forensic evidence.

Examples include:

* Documents
* Executables
* Archives
* Disk images
* Memory dumps

The database stores metadata only.

Actual files remain on secure storage.

### Typical Metadata

* Original filename
* Size
* SHA-256
* SHA-1
* MD5
* MIME type
* Upload date
* Associated case

---

## Analysis Job

### Purpose

Represents one execution of the analysis pipeline.

Each uploaded evidence item may generate one or more analysis jobs.

The analysis job tracks the complete execution lifecycle.

Typical states include:

* Queued
* Running
* Awaiting Review
* Completed
* Failed

---

## Finding

### Purpose

Represents an individual technical observation produced by an analyzer.

Each finding originates from one analysis engine.

Examples include:

* YARA match
* ClamAV detection
* High entropy
* Office macro
* PE metadata
* Suspicious strings

The pipeline consolidates all findings into the final assessment.

---

## Report

### Purpose

Represents a generated forensic report.

Reports summarize:

* Evidence
* Findings
* Risk assessment
* Expert decision
* Audit verification

Reports are generated after analysis and are intended for investigators and reviewers.

---

## Audit Event

### Purpose

Records every sensitive operation performed inside the platform.

Examples include:

* User login
* Case creation
* Evidence upload
* Analysis start
* Analysis completion
* Report generation
* Expert review

Audit events are append-only and linked using an HMAC chain to ensure traceability.

---

## AI Model

### Purpose

Stores metadata about machine learning models used by the platform.

Typical information includes:

* Model version
* Training date
* Performance metrics
* Feature manifest
* Active status

The trained model files themselves are stored outside the database.

---

# Database Lifecycle

A typical forensic investigation creates database records in the following order.

```text
Create User
        │
        ▼
Create Case
        │
        ▼
Upload Evidence
        │
        ▼
Create Analysis Job
        │
        ▼
Generate Findings
        │
        ▼
Generate Report
        │
        ▼
Record Audit Events
```

This lifecycle mirrors the operational workflow of the application.

---

# Database Design Principles

The database follows several design principles.

## Preserve Traceability

Every object can be traced back to its origin.

Relationships are maintained throughout the investigation.

---

## Preserve Integrity

Hashes, timestamps and identifiers are never modified after evidence ingestion.

---

## Separate Metadata from Binary Data

Large files are stored on dedicated storage volumes.

Only metadata is stored inside PostgreSQL.

This improves performance and simplifies backups.

---

## Maintain Referential Integrity

Objects are linked through foreign-key relationships.

Cases own evidence.

Evidence owns analyses.

Analyses own findings.

This organization simplifies navigation through an investigation.

---

## Support Future Extensions

The schema is designed to evolve without major redesign.

Future entities may include:

* Threat intelligence indicators
* IOC collections
* MITRE ATT&CK mappings
* VirusTotal results
* MISP objects
* Sigma rule matches

---

# Backup Strategy

The database is backed up together with evidence, reports and AI models.

Database dumps preserve:

* Users
* Cases
* Evidence metadata
* Findings
* Reports
* Audit chain

Binary evidence remains stored on dedicated persistent volumes.

---

# Database Best Practices

Developers should follow these recommendations.

* Never modify audit records manually.
* Never alter evidence hashes after ingestion.
* Avoid direct SQL updates outside application services.
* Preserve referential integrity.
* Prefer migrations over manual schema modifications.
* Keep metadata and binary evidence separated.

---

# Summary

The database is the persistent memory of MICEPP Scanner.

Rather than storing forensic files themselves, it stores the relationships, metadata and history required to reconstruct every investigation.

Its design supports forensic traceability, secure evidence management and future platform extensions while remaining independent of the analysis engines themselves.
