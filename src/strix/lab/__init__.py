"""Strix detection lab: a deliberately vulnerable loopback target, a versioned
oracle of what a scanner should and must not report, and a runner that scores
the real adapters against it (precision / recall / F1 per
``DETECTION_READINESS.md``).

The lab binds ``127.0.0.1`` only, serves static responses from a fixed routing
table, and never makes an outbound connection of its own.
"""

from strix.lab.evaluate import run_evaluation  # noqa: F401

__all__ = ["run_evaluation"]
