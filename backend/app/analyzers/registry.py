from __future__ import annotations

from typing import Iterable

from app.analyzers.base import BaseAnalyzer
from app.analyzers.clamav import ClamAVAnalyzer
from app.analyzers.office import OfficeAnalyzer
from app.analyzers.pdf import PDFAnalyzer
from app.analyzers.pe import PEAnalyzer
from app.analyzers.strings import SuspiciousStringsAnalyzer
from app.analyzers.yara import YaraAnalyzer


class AnalyzerRegistry:
    """
    Holds every registered analyzer.

    The pipeline simply executes every analyzer in order.
    """

    def __init__(self) -> None:
        self._analyzers: list[BaseAnalyzer] = []

        self.register(PEAnalyzer())
        self.register(OfficeAnalyzer())
        self.register(PDFAnalyzer())
        self.register(ClamAVAnalyzer())
        self.register(YaraAnalyzer())
        self.register(SuspiciousStringsAnalyzer())

    def register(self, analyzer: BaseAnalyzer) -> None:
        self._analyzers.append(analyzer)

    def analyzers(self) -> Iterable[BaseAnalyzer]:
        return self._analyzers
REGISTRY = AnalyzerRegistry()