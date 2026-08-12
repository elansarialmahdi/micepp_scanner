from __future__ import annotations

from pathlib import Path

import yara

from app.analyzers.base import BaseAnalyzer
from app.analyzers.types import AnalyzerFinding
from app.config import settings


class YaraAnalyzer(BaseAnalyzer):
    """
    Static analyzer based on YARA rules.

    Responsibilities:
    - Load all local YARA rules
    - Scan submitted files
    - Store metadata
    - Produce forensic findings
    """

    name = "yara"

    def _load_rules(self) -> yara.Rules:

        rule_files = (
            sorted(settings.yara_rules_root.glob("*.yar"))
            + sorted(settings.yara_rules_root.glob("*.yara"))
        )

        if not rule_files:
            raise FileNotFoundError(
                "Aucune règle YARA installée."
            )

        return yara.compile(
            filepaths={
                rule.stem: str(rule)
                for rule in rule_files
            },
            error_on_warning=False,
        )

    def _scan(
        self,
        path: Path,
    ) -> tuple[list[dict], str | None]:

        try:

            rules = self._load_rules()

            matches = rules.match(
                str(path),
                timeout=settings.yara_timeout_seconds,
            )

            results = []

            for match in matches:

                results.append(
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "mitre_ttp": match.meta.get("mitre_ttp"),
                    }
                )

            return results, None

        except Exception as exc:

            return [], f"{type(exc).__name__}: {exc}"

    def analyze(
        self,
        path: Path,
        features: dict,
        metadata: dict,
        findings: list[AnalyzerFinding],
    ) -> None:

        matches, error = self._scan(path)

        features["yara_match_count"] = float(len(matches))

        metadata["yara"] = {
            "matches": matches,
            "match_count": len(matches),
            "error": error,
        }

        for match in matches:

            severity = int(
                match["meta"].get(
                    "severity",
                    70,
                )
            )

            findings.append(
                AnalyzerFinding(
                    agent="agent-static",
                    category="yara",
                    severity=max(
                        1,
                        min(100, severity),
                    ),
                    title=f"Règle YARA : {match['rule']}",
                    description=str(
                        match["meta"].get(
                            "description",
                            "Correspondance avec une règle YARA locale.",
                        )
                    ),
                    confidence=0.90,
                    details=match,
                )
            )

        if error:

            findings.append(
                AnalyzerFinding(
                    agent="agent-static",
                    category="availability",
                    severity=10,
                    title="YARA indisponible",
                    description=error,
                    confidence=1.0,
                )
            )