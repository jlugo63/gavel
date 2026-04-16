"""
Compliance Export Bundles — SOC 2, ISO 42001, EU AI Act.

Enterprise customers need to hand auditors a single package that proves
their AI governance meets the relevant framework's requirements. This
package collects evidence from Gavel's audit trail, enrollment records,
RBAC decisions, incidents, and constitutional invariants, then structures
it into framework-specific export bundles.
"""

from __future__ import annotations

# Shared types
from gavel.compliance_exports.types import (
    ComplianceFramework,
    ControlStatus,
    ControlEvidence,
    ComplianceBundle,
)

# Exporter
from gavel.compliance_exports.exporter import ComplianceExporter

# File-based bundles
from gavel.compliance_exports.bundle import (
    BundleTarget,
    BundleFile,
    BundleControlEvidence,
    FileBundlePackage,
    BundleBuilder,
    build_eu_ai_act_bundle,
)

# Builders (for direct access)
from gavel.compliance_exports.builders import (
    build_soc2_evidence,
    build_iso42001_evidence,
    build_eu_ai_act_evidence,
)

__all__ = [
    # Types
    "ComplianceFramework",
    "ControlStatus",
    "ControlEvidence",
    "ComplianceBundle",
    # Exporter
    "ComplianceExporter",
    # File-based bundles
    "BundleTarget",
    "BundleFile",
    "BundleControlEvidence",
    "FileBundlePackage",
    "BundleBuilder",
    "build_eu_ai_act_bundle",
    # Builders
    "build_soc2_evidence",
    "build_iso42001_evidence",
    "build_eu_ai_act_evidence",
]
