# 09 – Security Architecture

# Security Overview

## Purpose

Security is one of the fundamental design principles of MICEPP Scanner.

Because the platform processes potentially malicious files and forensic evidence, every component has been designed to minimize risk while preserving evidence integrity and ensuring traceability.

Security is implemented as a cross-cutting concern affecting authentication, storage, analysis, deployment and auditing.

---

# Security Philosophy

The platform follows several core principles.

* Never trust uploaded files.
* Never execute evidence on the application server.
* Preserve forensic integrity.
* Apply least privilege.
* Ensure complete traceability.
* Require human validation.
* Protect sensitive information.

These principles guide every security decision within the application.

---

# Authentication

Access to the platform requires authentication.

The backend verifies user credentials before issuing a JSON Web Token (JWT).

Authentication protects all sensitive API endpoints.

---

# Password Security

User passwords are never stored in plaintext.

Passwords are protected using the Argon2 password hashing algorithm.

Argon2 provides resistance against:

* Brute-force attacks.
* Rainbow table attacks.
* GPU-based password cracking.

Password verification is performed securely before authentication succeeds.

---

# Authorization

After authentication, users receive permissions according to their assigned role.

Typical roles include:

* Administrator.
* Analyst.
* Reviewer.

Each role has access only to the operations required for its responsibilities.

This follows the Principle of Least Privilege.

---

# JWT Authentication

Authenticated sessions are managed using JSON Web Tokens.

JWT tokens contain authenticated user information and are verified on every protected request.

Tokens expire automatically after the configured lifetime, reducing the impact of credential theft.

---

# Evidence Integrity

Uploaded evidence is treated as immutable.

Immediately after upload the platform calculates:

* SHA-256
* SHA-1
* MD5

These cryptographic hashes uniquely identify the evidence.

The original file is preserved unchanged throughout the investigation.

Every later verification compares the stored hashes with newly calculated values to detect any modification.

---

# Secure Storage

Evidence is separated into two storage areas.

Original Evidence

* Immutable.
* Read-only.
* Never modified.

Working Copy

* Temporary.
* Used during analysis.
* May be safely manipulated.

This separation protects the integrity of forensic evidence.

---

# Secure File Upload

Uploaded files are never trusted.

Security mechanisms include:

* Streaming uploads.
* Upload size limits.
* Archive extraction limits.
* Safe path validation.
* MIME verification.
* Integrity verification.

These protections reduce the risk of malicious uploads targeting the platform itself.

---

# Archive Protection

Compressed archives are extracted using security controls.

Protections include:

* Zip Slip prevention.
* Tar Slip prevention.
* File count limits.
* Extraction size limits.

These controls prevent attackers from escaping the intended extraction directory or exhausting system resources.

---

# Static Analysis Safety

Static analyzers inspect artifacts without executing them.

This significantly reduces the attack surface while still allowing malware identification.

Examples include:

* YARA.
* ClamAV.
* File metadata analysis.
* Entropy calculation.
* String extraction.

---

# Dynamic Analysis Isolation

When enabled, dynamic analysis executes only inside a dedicated CAPE sandbox.

The sandbox is isolated from:

* Production systems.
* Internal networks.
* The application server.

Disposable virtual machines are used to prevent persistence between analyses.

The application server never executes uploaded malware.

---

# Docker Isolation

Application components execute inside isolated Docker containers.

Security measures include:

* Non-root containers.
* Removed Linux capabilities.
* Internal Docker networks.
* Limited service exposure.

These controls reduce the impact of container compromise.

---

# Audit Chain

Every sensitive action generates an audit event.

Examples include:

* Login.
* Case creation.
* Evidence upload.
* Analysis execution.
* Report generation.
* Human review.

Audit events are linked together using HMAC-SHA-256.

This prevents undetected modification of the investigation history.

---

# Human Validation

Automated analysis never represents the final decision.

Every investigation requires human review before being considered complete.

This prevents automated systems from becoming the sole source of forensic conclusions.

---

# Secrets Management

Sensitive configuration values are stored outside the application source code.

Typical secrets include:

* JWT signing keys.
* HMAC keys.
* Database credentials.
* Administrator credentials.
* Sandbox API tokens.

Production deployments should store secrets inside a dedicated secrets management solution.

---

# Backup Security

Backups preserve:

* Database.
* Evidence.
* Reports.
* AI models.

Integrity verification accompanies backups to ensure that restored data remains trustworthy.

Backups should be encrypted and stored separately from the production environment.

---

# Network Security

Only required services are exposed externally.

Internal services communicate through isolated Docker networks.

Examples of internal-only services include:

* PostgreSQL.
* Redis.
* Worker.
* ClamAV.

This minimizes the external attack surface.

---

# Security Monitoring

Operational monitoring should include:

* Authentication failures.
* Audit verification failures.
* Analysis failures.
* Container health.
* Integrity violations.

Rapid detection of abnormal events improves incident response.

---

# Future Security Improvements

Potential enhancements include:

* Multi-factor authentication.
* Hardware security modules.
* SSO integration.
* Certificate-based authentication.
* Automatic secret rotation.
* SIEM integration.
* IDS/IPS integration.
* Immutable object storage.
* Secure hardware enclaves.
* Kubernetes security policies.

The current architecture is designed to accommodate these improvements without major redesign.

---

# Security Principles Summary

MICEPP Scanner applies multiple layers of defense rather than relying on a single security mechanism.

Authentication, authorization, immutable evidence, isolated execution, cryptographic integrity verification, audit chaining and container isolation work together to protect both the platform and the forensic evidence.

This layered approach aligns with modern cybersecurity and digital forensics best practices.

---

# Conclusion

Security is integrated into every stage of the MICEPP Scanner lifecycle.

Rather than treating security as an additional feature, the platform incorporates it into its architecture, ensuring that investigations remain trustworthy, reproducible and resistant to tampering.
