# 05 – Analyzers

# Analyzer Architecture

## Purpose

Analyzers are the core detection components of MICEPP Scanner.

Each analyzer is responsible for performing one specific type of forensic inspection on an artifact.

Rather than implementing one large monolithic scanner, MICEPP separates each analysis technique into independent modules coordinated by the Analysis Pipeline.

This modular architecture simplifies maintenance and allows new analysis engines to be integrated without redesigning the application.

---

# Overall Architecture

```text id="6q7l21"
                Analysis Pipeline
                       │
 ┌─────────────────────┼──────────────────────┐
 │                     │                      │
 ▼                     ▼                      ▼
Extractor        Static Analysis       AI Analysis
 │                     │                      │
 ▼                     ▼                      ▼
Artifacts        Findings            Prediction
 │                     │                      │
 └─────────────────────┼──────────────────────┘
                       │
                       ▼
              Finding Normalization
                       │
                       ▼
               Risk Consolidation
```

Each analyzer performs a specialized task and returns standardized results.

---

# Analyzer Principles

Every analyzer follows the same philosophy:

* One responsibility.
* No direct communication with other analyzers.
* Independent execution.
* Structured output.
* Easy replacement.
* Easy extension.

This keeps the platform modular and maintainable.

---

# Extractor Analyzer

## Purpose

The extractor prepares artifacts before analysis.

It handles compressed archives and forensic disk images by extracting their contents into an isolated working directory.

Typical supported formats include:

* ZIP
* TAR
* RAW
* E01

The original evidence is never modified.

---

## Responsibilities

* Create working copies.
* Extract archives.
* Recover forensic image contents.
* Protect against path traversal.
* Limit extraction size.
* Prepare artifacts for analysis.

---

## Output

The extractor returns:

* Extracted files
* Metadata
* Extraction status
* Possible extraction errors

---

# Static Analyzer

## Purpose

The static analyzer inspects artifacts without executing them.

It searches for indicators that may reveal malicious behavior while preserving complete safety.

---

## Static Analysis Techniques

Examples include:

* MIME detection
* File entropy
* String extraction
* PE inspection
* Office macro detection
* PDF active content inspection
* YARA rule matching
* ClamAV signature scanning

These techniques are deterministic and reproducible.

---

## Output

The analyzer produces structured findings including:

* Category
* Severity
* Confidence
* Technical details
* Description

---

# YARA Engine

## Purpose

YARA identifies malware families and suspicious patterns using custom rules.

Rules describe known malicious characteristics instead of relying solely on antivirus signatures.

Examples include:

* Embedded URLs
* Suspicious imports
* Shellcode patterns
* Obfuscation techniques
* Malware family identifiers

---

## Advantages

* Highly customizable.
* Fast execution.
* Excellent for malware classification.
* Easy to extend.

New rules can be added without modifying application code.

---

# ClamAV Engine

## Purpose

ClamAV performs traditional signature-based malware detection.

It compares uploaded artifacts against an updated malware signature database.

Typical detections include:

* Known malware
* Trojan families
* Worms
* Backdoors
* Exploit kits

ClamAV complements YARA by detecting threats already present in its signature database.

---

# Machine Learning Analyzer

## Purpose

The machine learning analyzer evaluates artifacts using a supervised classification model.

Unlike YARA or ClamAV, it attempts to detect previously unseen threats based on learned characteristics.

---

## Workflow

1. Feature extraction
2. Feature normalization
3. Model prediction
4. Confidence calculation
5. Probability estimation

If no trained model exists, the analyzer reports that machine learning is unavailable without interrupting the rest of the analysis.

---

# Dynamic Analyzer (CAPE Sandbox)

## Purpose

The dynamic analyzer executes suspicious artifacts inside an isolated virtual environment.

Unlike static analysis, it observes the behavior of the artifact during execution.

---

## Typical Observations

* Process creation
* File modifications
* Registry changes
* Network connections
* Persistence mechanisms
* Child processes

Because execution occurs inside a dedicated sandbox, the application server remains protected.

---

## Optional Component

Dynamic analysis only runs when a CAPE sandbox has been configured.

If unavailable, the platform explicitly reports that dynamic analysis was skipped.

No simulated findings are generated.

---

# Finding Normalization

Every analyzer produces its own raw results.

Before consolidation, all outputs are converted into a common structure.

Typical fields include:

* Analyzer name
* Category
* Severity
* Confidence
* Description
* Technical details

Normalization allows the pipeline to compare heterogeneous analysis engines consistently.

---

# Risk Contribution

Each analyzer contributes part of the overall forensic assessment.

Examples:

| Analyzer         | Main Contribution         |
| ---------------- | ------------------------- |
| Extractor        | Artifact preparation      |
| YARA             | Pattern matching          |
| ClamAV           | Signature detection       |
| Static Analysis  | Structural inspection     |
| Machine Learning | Behavioral classification |
| CAPE             | Runtime behavior          |

The pipeline combines these observations into the final automated verdict.

---

# Adding a New Analyzer

The architecture has been designed to simplify future integrations.

Typical steps are:

1. Create a new analyzer module.
2. Implement a standardized result format.
3. Register the analyzer in the pipeline.
4. Normalize its findings.
5. Include its contribution in the final risk calculation.

No redesign of the existing analyzers is required.

---

# Future Integrations

The current architecture can accommodate additional detection engines such as:

* VirusTotal
* Hybrid Analysis
* MISP
* OpenCTI
* Sigma rules
* CAPA
* FLOSS
* Cuckoo-compatible sandboxes
* MITRE ATT&CK mapping

Each integration would become another independent analyzer coordinated by the pipeline.

---

# Design Advantages

The analyzer architecture provides several benefits:

* Clear separation of responsibilities.
* Independent evolution of detection engines.
* Easier testing and debugging.
* Consistent result formatting.
* High extensibility.
* Reduced coupling between components.

This modular design allows MICEPP Scanner to evolve by incorporating new forensic technologies while preserving the stability of the existing platform.
