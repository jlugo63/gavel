"""ComplianceExporter — generates compliance bundles for supported frameworks."""

from __future__ import annotations

from typing import Any, Optional

from gavel.compliance_exports.types import (
    ComplianceBundle,
    ComplianceFramework,
)
from gavel.compliance_exports.builders.soc2 import build_soc2_evidence
from gavel.compliance_exports.builders.iso42001 import build_iso42001_evidence
from gavel.compliance_exports.builders.eu_ai_act import build_eu_ai_act_evidence


class ComplianceExporter:
    """Generate compliance export bundles for supported frameworks."""

    def __init__(self, context: Optional[dict[str, Any]] = None):
        self._context = context or {}

    def export(self, framework: ComplianceFramework) -> ComplianceBundle:
        """Generate a compliance bundle for the given framework."""
        if framework == ComplianceFramework.SOC2:
            controls = build_soc2_evidence(self._context)
            version = "SOC 2 Type II (AICPA 2017)"
        elif framework == ComplianceFramework.ISO_42001:
            controls = build_iso42001_evidence(self._context)
            version = "ISO/IEC 42001:2023"
        elif framework == ComplianceFramework.EU_AI_ACT:
            controls = build_eu_ai_act_evidence(self._context)
            version = "EU AI Act (Regulation 2024/1689)"
        else:
            raise ValueError(f"Unsupported framework: {framework}")

        bundle = ComplianceBundle(
            framework=framework,
            framework_version=version,
            controls=controls,
        )
        bundle.finalize()
        return bundle

    def export_all(self) -> list[ComplianceBundle]:
        """Generate compliance bundles for all supported frameworks."""
        return [self.export(fw) for fw in ComplianceFramework]
