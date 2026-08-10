from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalyzerFinding:
    """
    Standardized result returned by every analyzer.
    """

    agent: str
    category: str
    severity: int
    title: str
    description: str
    confidence: float | None = None
    details: dict = field(default_factory=dict)


@dataclass
class StaticResult:
    """
    Final result returned by the static analysis pipeline.
    """

    mime_type: str
    features: dict[str, float]
    metadata: dict
    findings: list[AnalyzerFinding]
    risk_score: float