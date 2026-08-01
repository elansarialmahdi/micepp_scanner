# 02 – Backend Architecture

# Backend Overview

The backend is the core component of the MICEPP Scanner platform.

It is responsible for receiving user requests, authenticating users, managing forensic cases and evidence, orchestrating malware analysis, generating forensic reports, maintaining the audit trail and exposing the REST API consumed by the frontend.

Unlike the frontend, which only displays information, every security-critical operation is implemented inside the backend.

---

# Backend Directory Structure

```text
backend/

app/
│
├── analyzers/
├── api.py
├── audit.py
├── config.py
├── database.py
├── main.py
├── models.py
├── pipeline.py
├── reports.py
├── schemas.py
├── security.py
├── storage.py
└── worker.py
```

Each file has a single responsibility and communicates with the others through well-defined interfaces.

---

# Backend Architecture

The backend follows a layered architecture.

```text
HTTP Request

↓

FastAPI Router

↓

Authentication

↓

Business Logic

↓

Database / Storage

↓

Analysis Pipeline

↓

Response
```

This separation makes the project easier to maintain and extend.

---

# Core Components

## main.py

This is the application entry point.

Responsibilities:

* Creates the FastAPI application.
* Registers middleware.
* Initializes the application lifecycle.
* Exposes health endpoints.
* Starts the backend service.

Every request enters the application through this file before being routed to the appropriate API endpoint.

---

## api.py

This file exposes every REST endpoint.

Responsibilities include:

* User authentication
* Case management
* Evidence upload
* Analysis management
* Report download
* AI model operations
* Audit verification

The API layer should remain lightweight.

Its responsibility is to validate requests, invoke the appropriate backend services and return structured responses.

Business logic should remain outside the router whenever possible.

---

## config.py

Centralizes application configuration.

Configuration values are loaded from environment variables through Pydantic Settings.

Examples include:

* Database connection
* Upload limits
* JWT lifetime
* CAPE configuration
* Storage paths
* Security options

Centralizing configuration allows the application to be deployed in different environments without changing the source code.

---

## database.py

Responsible for database initialization.

Responsibilities include:

* SQLAlchemy engine creation
* Session management
* Connection lifecycle
* Database dependency injection

Every database operation passes through the session provided here.

---

## models.py

Defines the relational data model.

This file contains all SQLAlchemy entities representing objects stored in PostgreSQL.

Examples include:

* Users
* Cases
* Evidence
* Analysis jobs
* Findings
* AI models
* Audit events

Relationships between entities are also declared here.

---

## schemas.py

Defines the API contracts.

Unlike database models, schemas describe how data is exchanged through the REST API.

Responsibilities:

* Request validation
* Response serialization
* Type safety
* OpenAPI documentation generation

This separation prevents exposing database entities directly to API clients.

---

## security.py

Implements authentication and authorization.

Responsibilities include:

* Password hashing
* Password verification
* JWT creation
* JWT validation
* Current-user resolution
* Role-based authorization

Every protected endpoint depends on this module before executing business logic.

---

## storage.py

Responsible for secure evidence handling.

Main responsibilities:

* Streaming uploads
* Hash computation
* Secure storage
* Working copy creation
* Path validation
* File integrity verification

This module guarantees that original evidence remains preserved while analyses are executed on isolated working copies.

---

## pipeline.py

The orchestration engine of MICEPP.

This is the most important backend component.

Responsibilities:

* Verify integrity
* Extract artifacts
* Execute static analyzers
* Execute machine learning
* Execute CAPE sandbox (when configured)
* Consolidate findings
* Compute risk
* Produce the final analysis state

Rather than performing analysis itself, this module coordinates the different analysis engines.

---

## analyzers/

Contains all analysis engines.

Each analyzer performs a specialized task.

Examples include:

* Static analysis
* Feature extraction
* Machine learning
* Archive extraction
* CAPE integration

Each analyzer returns normalized findings that are later consolidated by the pipeline.

This modular design allows additional analyzers to be integrated with minimal impact on the rest of the application.

---

## worker.py

Background execution service.

Heavy analysis operations are not executed directly by the API.

Instead:

1. The API creates an analysis job.
2. The job is sent to Redis.
3. Celery executes the job asynchronously.
4. The worker invokes the analysis pipeline.

This architecture keeps the REST API responsive while long-running analyses continue in the background. The repository currently defines a single Celery analysis task backed by Redis.

---

## reports.py

Responsible for forensic report generation.

After analysis and expert review, this module generates a PDF report containing:

* Evidence metadata
* Integrity hashes
* Findings
* Risk assessment
* Expert decision
* Audit information

Reports are intended to provide a traceable summary of the completed analysis.

---

## audit.py

Implements the forensic audit chain.

Every sensitive operation creates a new audit event.

Events are linked together using cryptographic HMAC chaining, allowing later verification that the audit history has not been modified.

The audit chain is a key component supporting forensic traceability.

---

# Backend Request Lifecycle

A typical request follows this path:

```text
Client

↓

FastAPI Endpoint

↓

Authentication

↓

Request Validation

↓

Business Logic

↓

Database

↓

Pipeline (if required)

↓

Response
```

Long-running operations are delegated to the worker instead of blocking the HTTP request.

---

# Backend Design Principles

The backend follows several architectural principles:

* Separation of concerns.
* Immutable forensic evidence.
* Human-supervised decision making.
* Modular analysis engines.
* Background execution for expensive operations.
* Centralized configuration.
* Strong typing through SQLAlchemy and Pydantic.
* Security-first design.
* Complete auditability.

These principles make the backend easier to extend while preserving forensic integrity.

---

# Extension Points

The backend was intentionally designed to support future integrations.

Potential extensions include:

* VirusTotal
* MISP
* OpenCTI
* Hybrid Analysis
* Sigma rule execution
* MITRE ATT&CK mapping
* Additional AI models
* New report formats
* Enterprise authentication providers

Most future capabilities can be implemented by extending existing modules rather than redesigning the architecture.

