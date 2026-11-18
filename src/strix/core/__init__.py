"""Core assessment engine: authorization gate, adapters, jobs, and storage.

This is a namespace package — import submodules directly:
    from strix.core import adapters
    from strix.core import jobs
    ...
"""

__all__ = [
    "adapter_base",
    "adapters",
    "authz",
    "collab",
    "crawler",
    "compliance_report",
    "evidence",
    "exceptions",
    "exceptions_worker",
    "exposure",
    "findings",
    "jobs",
    "k8s_job_runner",
    "k8s_queue",
    "locks",
    "mssp",
    "org",
    "oidc",
    "organizations",
    "policies",
    "ports",
    "pricing",
    "probe",
    "queue",
    "redaction",
    "sandbox",
    "scheduler",
    "scope",
    "signatures",
    "store",
    "tenants",
    "urls",
    "worker",
]
