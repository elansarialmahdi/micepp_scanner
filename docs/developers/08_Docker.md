# 08 – Docker Architecture

# Docker Overview

## Purpose

MICEPP Scanner is deployed using Docker and Docker Compose.

Containerization ensures that every component of the platform executes inside an isolated environment with reproducible configurations and simplified deployment.

Instead of installing every dependency directly on the host operating system, each service runs inside its own dedicated container.

---

# Deployment Architecture

The platform is composed of several independent services.

```text id="f9g4kx"
                User
                  │
                  ▼
              Web Browser
                  │
                  ▼
           React Frontend (Nginx)
                  │
                  ▼
            FastAPI Backend
                  │
      ┌───────────┴────────────┐
      ▼                        ▼
 PostgreSQL               Redis Queue
      │                        │
      └───────────┬────────────┘
                  ▼
            Celery Worker
                  │
      ┌───────────┴────────────┐
      ▼                        ▼
    ClamAV                CAPE Sandbox
 (optional)              (optional)
```

Each service has a dedicated responsibility and communicates only with the services it requires.

---

# Container Overview

The platform consists of the following containers.

---

## Frontend

Responsibilities:

* Serve the React application.
* Reverse proxy API requests.
* Expose the web interface.
* Handle static assets.

Only this container is directly accessible to users.

---

## Backend

Responsibilities:

* REST API.
* Authentication.
* Case management.
* Evidence ingestion.
* Analysis orchestration.
* Report generation.
* Audit management.

This is the central application server.

---

## Worker

Responsibilities:

* Execute background analysis jobs.
* Process Celery tasks.
* Run malware analysis pipeline.
* Generate findings.

Separating the worker from the API prevents long-running analyses from blocking user requests.

---

## PostgreSQL

Responsibilities:

* Store persistent metadata.
* User accounts.
* Cases.
* Evidence metadata.
* Findings.
* Reports.
* Audit events.

Binary evidence is stored outside the database.

---

## Redis

Responsibilities:

* Message broker.
* Task queue.
* Communication between API and worker.

Redis does not permanently store forensic information.

---

## ClamAV

Responsibilities:

* Signature updates.
* Malware scanning.
* Antivirus detection.

Only the ClamAV container requires external access for downloading signature updates when online.

---

## CAPE Sandbox (Optional)

Responsibilities:

* Dynamic malware execution.
* Behavioral analysis.
* Runtime observation.

This component is deployed separately from the main application for security reasons.

---

# Docker Networks

The platform separates services using dedicated Docker networks.

Typical communication flow:

```text id="lh72mz"
Frontend

↓

Backend

↓

Database
Redis
Worker

↓

ClamAV
CAPE
```

This isolation reduces unnecessary network exposure.

---

# Persistent Volumes

Persistent Docker volumes preserve important information.

Typical volumes include:

* PostgreSQL database.
* Original evidence.
* Working directory.
* Generated reports.
* AI models.
* ClamAV signatures.

Containers may be recreated without losing forensic data.

---

# Startup Process

A typical startup sequence is:

```text id="mc41ph"
Load .env

↓

Build Images

↓

Start PostgreSQL

↓

Start Redis

↓

Start Backend

↓

Start Worker

↓

Start Frontend

↓

Health Checks

↓

Platform Ready
```

Docker Compose automatically manages service dependencies and health verification.

---

# Environment Configuration

Application configuration is stored in environment variables.

Typical configuration categories include:

* Database credentials.
* JWT settings.
* Upload limits.
* CAPE configuration.
* ClamAV options.
* Security keys.
* Network settings.

Environment-specific configuration is separated from the application source code.

---

# Health Checks

Each critical service exposes a health status.

Docker Compose waits until required services become healthy before completing startup.

Typical health checks include:

* PostgreSQL availability.
* Redis connectivity.
* Backend readiness.
* Frontend availability.
* ClamAV status.

This improves deployment reliability.

---

# Daily Operations

Typical maintenance commands include:

Start services

```bash
docker compose up -d
```

Stop services

```bash
docker compose stop
```

Restart services

```bash
docker compose restart
```

View running containers

```bash
docker compose ps
```

View logs

```bash
docker compose logs -f
```

Rebuild containers

```bash
docker compose up -d --build
```

These commands cover most day-to-day administration tasks.

---

# Backup Strategy

Backups include:

* PostgreSQL database.
* Original evidence.
* Reports.
* AI models.
* Integrity verification files.

The backup process preserves both metadata and forensic artifacts while maintaining traceability.

---

# Security Considerations

The Docker deployment follows several security principles.

* Non-root containers.
* Internal-only services.
* Restricted network exposure.
* Persistent storage separation.
* Environment-based secrets.
* Dedicated analysis containers.

These measures reduce the attack surface of the platform.

---

# Advantages of Containerization

Using Docker provides several benefits.

* Reproducible deployments.
* Simplified installation.
* Dependency isolation.
* Easy updates.
* Service separation.
* Portable environments.
* Simplified maintenance.

Containerization also makes future cloud or on-premises deployments easier.

---

# Future Improvements

Potential infrastructure enhancements include:

* Kubernetes deployment.
* High availability.
* Horizontal worker scaling.
* Distributed task queues.
* Object storage integration.
* Automated CI/CD deployments.
* Container vulnerability scanning.
* Monitoring with Prometheus and Grafana.

The current Docker architecture provides a solid foundation for future growth.

---

# Summary

Docker provides the infrastructure layer of MICEPP Scanner.

By isolating each service into dedicated containers, the platform achieves portability, maintainability and security while supporting asynchronous malware analysis and forensic workflows.
