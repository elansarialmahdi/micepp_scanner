from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.analyzers.types import AnalyzerFinding


class BaseAnalyzer(ABC):
    """
    Base class implemented by every analyzer.

    Each analyzer receives the current file together with
    the mutable analysis context and can enrich it.
    """

    name: str = "base"

    @abstractmethod
    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:
        """
        Perform the analysis.

        Implementations should update:
            - features
            - metadata
            - findings

        They must never return a value.
        """
        raise NotImplementedError