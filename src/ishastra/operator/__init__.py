"""Ishastra Kubernetes Operator - CRD Controllers for AssessmentJob, Tenant, Policy, ScanResult."""

from __future__ import annotations

__all__ = [
    "main",
    "run_operator",
]

from ishastra.operator.main import main, run_operator
