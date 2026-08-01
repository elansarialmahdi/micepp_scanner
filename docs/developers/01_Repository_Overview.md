# 01 – Repository Overview

## MICEPP Scanner – Repository Overview

**Version:** 1.0
**Audience:** Developers and Contributors

---

# 1. Purpose

MICEPP Scanner is a web-based forensic malware analysis platform designed to operate inside a secure intranet environment.

The platform enables analysts to upload digital evidence, verify its integrity, execute multiple analysis engines, collect technical findings, generate forensic reports, and maintain a complete audit trail while ensuring that every important decision remains under human supervision.

Unlike traditional antivirus software, MICEPP Scanner is designed as a forensic analysis platform where evidence preservation, traceability, and reproducibility are considered as important as malware detection itself.

---

# 2. Development Philosophy

Several principles guided the architecture of the project.

## Preserve Evidence

The original uploaded file is never modified.

Every uploaded artifact is preserved separately and becomes read-only immediately after ingestion.

All analyses are executed on isolated working copies.

---

## Never Trust Uploaded Files

Uploaded files are considered potentially malicious.

The application server never executes user files.

Dynamic execution belongs only to a dedicated sandbox (CAPE/Cuckoo) running on an isolated infrastructure.

---

## Human-Centered Analysis

Automatic analysis assists the analyst but never replaces human expertise.

Machine Learning predictions, static analysis and sandbox results provide technical assistance only.

The final decision always belongs to an authorized reviewer.

---

## Complete Traceability

Every sensitive action performed inside the platform is permanently recorded.

Authentication, evidence ingestion, analysis execution, report generation and expert validation are linked together through a cryptographically verifiable audit chain.

---

## Modular Architecture

Each subsystem has a clearly defined responsibility.

The project is organized so that new analyzers, AI models and external integrations can be added with minimal impact on the existing codebase.

---

# 3. Repository Organization

The repository is divided into several major components.

```
MICEPP Scanner

backend/
Core FastAPI application

frontend/
React user interface

docs/
Technical and functional documentation

scripts/
Automation utilities

migrations/
Database schema evolution

docker-compose.yml
Complete application stack
```

Each component has a single responsibility and communicates with the others through well-defined interfaces.

---

# 4. Component Responsibilities

## Backend

The backend is the core of the application.

It contains:

* REST API
* Authentication
* Evidence management
* Analysis orchestration
* Report generation
* Audit system
* AI integration
* Background processing

All business logic resides inside the backend.

---

## Frontend

The frontend provides the user interface used by analysts, reviewers and administrators.

Its responsibilities include:

* User authentication
* Dashboard
* Case management
* Evidence upload
* Analysis visualization
* Human validation
* Audit visualization
* AI model management

The frontend communicates exclusively with the backend API.

---

## Documentation

The documentation folder contains project documentation.

It serves both developers and system administrators.

Future developer documentation is located inside:

```
docs/developer/
```

---

## Scripts

The scripts directory automates repetitive operations.

Typical responsibilities include:

* Initial deployment
* Environment bootstrap
* Backup
* Restore
* Maintenance

These scripts reduce manual configuration and help ensure reproducible deployments.

---

## Database Migrations

Database migrations define the evolution of the PostgreSQL schema.

They ensure that every deployment shares the same database structure while preserving existing data.

---

# 5. Runtime Architecture

During execution, the application is composed of multiple isolated services.

```
React Frontend
        │
        ▼
FastAPI API
        │
        ├──────────────► PostgreSQL
        │
        ├──────────────► Redis
        │
        ▼
Celery Worker
        │
        ├──────────────► Static Analysis
        ├──────────────► Machine Learning
        └──────────────► CAPE Sandbox (optional)
```

Each service performs a specific role while remaining isolated from the others.

---

# 6. High-Level Workflow

A typical forensic analysis follows these steps.

1. An analyst creates a forensic case.
2. Digital evidence is uploaded.
3. Integrity hashes are calculated.
4. The original evidence is preserved.
5. A working copy is created.
6. Static analyzers inspect the artifact.
7. Machine Learning evaluates extracted features.
8. The sandbox executes the artifact if configured.
9. Findings are consolidated.
10. A risk assessment is generated.
11. A reviewer validates the final decision.
12. A forensic report is produced.
13. Every operation is recorded in the audit chain.

---

# 7. Security Principles

The platform follows several security principles.

* Original evidence is immutable.
* Application containers execute without unnecessary privileges.
* Sensitive services remain internal to Docker.
* Authentication uses modern password hashing.
* Every important action is audited.
* Human review is mandatory before final validation.
* Dynamic execution is isolated from the application server.

---

# 8. Extension Points

The project was designed to evolve.

Examples of future integrations include:

* Additional malware analyzers
* Threat intelligence platforms
* New AI models
* Behavioral analysis engines
* Additional forensic report formats
* Enterprise authentication providers
* SIEM integration
* Vulnerability intelligence services

Most new capabilities should integrate into existing modules rather than requiring architectural changes.

---

# 9. Where to Start as a Developer

Developers joining the project are encouraged to study the repository in the following order.

1. Repository Overview (this document)
2. Backend Architecture
3. Analysis Pipeline
4. Database
5. Analyzers
6. AI System
7. Frontend
8. Docker & Deployment
9. Security
10. Extension Guide

Following this order provides a progressive understanding of both the architecture and the forensic workflow.

---

# 10. Documentation Roadmap

This document is the entry point of the developer documentation.

The following documents provide progressively deeper technical details.

* 01 – Repository Overview
* 02 – Backend
* 03 – Database
* 04 – Analysis Pipeline
* 05 – Analyzers
* 06 – AI System
* 07 – Frontend
* 08 – Docker
* 09 – Security
* 10 – Extending MICEPP

Together, these documents describe both how the platform currently works and how it can be safely extended in future versions.

