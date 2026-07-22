from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from app.analyzers.features import FEATURE_NAMES, vectorize
from app.config import settings


def predict(features: dict, model_path: str | None) -> tuple[float | None, dict]:
    if not model_path:
        return None, {"status": "not_trained", "reason": "Aucun modèle validé n'est actif"}
    bundle = joblib.load(model_path)
    probability = float(bundle["model"].predict_proba([vectorize(features)])[0][1])
    return probability, {"status": "predicted", "version": bundle["version"], "feature_names": FEATURE_NAMES}


def train(entries: list[tuple[str, dict, int]], trained_by: str) -> dict:
    labels = [label for _artifact_id, _features, label in entries]
    benign = labels.count(0)
    malicious = labels.count(1)
    minimum = settings.model_min_samples_per_class
    if benign < minimum or malicious < minimum:
        raise ValueError(
            f"Entraînement refusé: {minimum} échantillons réels par classe sont requis "
            f"(bénins={benign}, malveillants={malicious})"
        )
    manifest = [
        {"artifact_id": artifact_id, "label": label, "features": {k: features.get(k, 0) for k in FEATURE_NAMES}}
        for artifact_id, features, label in sorted(entries)
    ]
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    x = [vectorize(features) for _artifact_id, features, _label in entries]
    y = labels
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, output_dict=True, zero_division=0),
        "training_samples": len(x_train),
        "test_samples": len(x_test),
        "benign_samples": benign,
        "malicious_samples": malicious,
    }
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    version = f"rf-{timestamp}-{manifest_hash[:8]}"
    model_path = settings.model_root / f"{version}.joblib"
    bundle = {
        "model": model,
        "version": version,
        "feature_names": FEATURE_NAMES,
        "manifest_hash": manifest_hash,
        "trained_by": trained_by,
        "metrics": metrics,
    }
    joblib.dump(bundle, model_path, compress=3)
    return {
        "version": version,
        "path": str(model_path),
        "features": FEATURE_NAMES,
        "manifest_hash": manifest_hash,
        "metrics": metrics,
    }
