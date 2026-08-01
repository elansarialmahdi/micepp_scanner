# 06 – AI System

# Artificial Intelligence System

## Purpose

The Artificial Intelligence (AI) system assists forensic analysts by estimating the probability that an analyzed artifact is malicious.

The AI component is designed to support expert decision-making rather than replace it.

Its predictions are considered one source of information among several others, including static analysis, signature-based detection and dynamic analysis.

---

# Design Philosophy

Unlike many antivirus solutions, the AI system does **not** make autonomous decisions.

The guiding principles are:

* Human supervision is mandatory.
* AI assists the analyst.
* Expert validation remains the final authority.
* The AI model continuously improves from validated investigations.

This approach follows the "Human in the Loop" principle.

---

# AI Workflow

The AI module participates in the analysis pipeline after static analysis.

```text id="j9v1xt"
Evidence

↓

Static Analysis

↓

Feature Extraction

↓

Machine Learning Model

↓

Prediction

↓

Risk Consolidation

↓

Human Review
```

If the AI model is unavailable, the pipeline continues normally without interruption.

---

# Feature Extraction

Before classification, the system extracts numerical features from the analyzed artifact.

Examples of feature categories include:

* File metadata
* File size
* Entropy measurements
* MIME type
* Static analysis indicators
* YARA matches
* ClamAV results
* Structural characteristics

These features are transformed into a numerical representation suitable for machine learning.

---

# Supervised Learning

The current implementation uses supervised learning.

This means the model is trained only on artifacts that have been reviewed and classified by an expert.

Typical labels include:

* Benign
* Malicious

Only validated samples contribute to future training.

This prevents unreliable or automatically generated labels from contaminating the training dataset.

---

# Model Lifecycle

The AI model follows a controlled lifecycle.

```text id="4h80zl"
New Evidence

↓

Expert Review

↓

Ground Truth Label

↓

Training Dataset

↓

Model Training

↓

Performance Evaluation

↓

Model Deployment
```

A newly trained model replaces the previous version only after successful evaluation.

---

# Model Versioning

Each trained model is versioned.

Typical metadata includes:

* Version identifier
* Training date
* Performance metrics
* Feature manifest
* Activation status

Older versions remain available for traceability and comparison.

---

# Training Requirements

The system avoids training on insufficient data.

Training begins only after enough validated examples exist for each class.

This reduces the risk of producing unreliable models.

---

# Prediction Output

When a trained model is available, the AI component returns:

* Predicted class
* Confidence score
* Probability estimate
* Model version used

These results are combined with the findings produced by the other analyzers.

---

# Human in the Loop

The AI never replaces the forensic expert.

The reviewer may:

* Accept the prediction.
* Reject the prediction.
* Request additional investigation.
* Correct the classification.

The corrected decision becomes the new ground truth for future model training.

This continuous feedback loop improves the quality of future models.

---

# Current Limitations

At the current stage of development:

* No pretrained model is delivered with the platform.
* Predictions are unavailable until a model has been trained.
* The model learns only from validated forensic investigations.
* AI is one component of the overall assessment and never the sole decision maker.

This design prioritizes forensic reliability over automation.

---

# Future Evolution

The AI architecture has been designed to support more advanced capabilities without modifying the overall analysis pipeline.

Potential future improvements include:

* Behavioral malware detection.
* Threat intelligence enrichment.
* Deep learning models.
* Malware family classification.
* Explainable AI techniques.
* Automatic feature selection.
* Ensemble learning.
* Incremental model updates.

The modular design allows new AI models to coexist with the existing pipeline.

---

# Long-Term Vision

The long-term objective is to transform the AI component from a simple supervised classifier into an intelligent forensic assistant capable of combining multiple sources of evidence.

Possible information sources include:

* Static analysis results.
* Dynamic sandbox behavior.
* Threat intelligence platforms.
* Malware reputation databases.
* Historical investigations.
* Expert feedback.

Rather than relying on a single prediction, the AI would correlate information from several independent sources before estimating the overall risk.

---

# Design Principles

The AI subsystem follows several fundamental principles:

* Expert supervision.
* Traceability.
* Reproducibility.
* Version control.
* Continuous improvement.
* Transparency.
* Separation between prediction and final decision.

These principles ensure that artificial intelligence enhances forensic investigations while preserving accountability and evidentiary integrity.

---

# Summary

The AI system is an assistive component within MICEPP Scanner.

It analyzes validated forensic features, estimates the likelihood of malicious activity, and continuously improves through expert feedback.

By combining supervised learning with human review, the platform provides intelligent decision support while ensuring that final responsibility always remains with the forensic analyst.
