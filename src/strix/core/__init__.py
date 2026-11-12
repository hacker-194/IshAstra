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
    "exposure",
    "findings",
    "jobs",
    "locks",
    "policies",
    "ports",
    "probe",
    "redaction",
    "scope",
    "signatures",
    "store",
    "urls",
    "worker",
]
