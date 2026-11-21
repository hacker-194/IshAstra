"""Adapter primitives shared by the built-in detectors and external tools.

Kept in its own module so a detector module (``exposure``, ``ports``) can
implement an adapter without importing ``ishastra.core.adapters`` — which imports
them in turn to build the registry.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ishastra.core.findings import Finding
from ishastra.core.scope import Destination, get_pinned_destination
from ishastra.core.scope import destination as scope_destination
from ishastra.core.urls import parse_url


def checked_destination(target: str) -> Destination:
    """The pinned destination for ``target``, or ``AdapterError`` when the
    scope gate refuses it. This is the *single* choke point: no adapter can
    bypass the scope gate, even internally. Every outbound connection from
    any adapter must go through this function, or the scope check is skipped.

    Uses a pre-pinned destination from the job execution context if available
    (set by ``execute()`` after the initial scope check) to avoid TOCTOU
    between the gate check and the adapter's connect-time resolution.
    """
    pinned = get_pinned_destination()
    if pinned is not None:
        parsed = parse_url(target)
        if parsed and parsed.hostname and parsed.hostname.lower() == pinned.host:
            return pinned

    denial, reason, destination = scope_destination(target)
    if denial or destination is None:
        raise AdapterError(f"scope refused {target}: {reason or 'destination unavailable'}")
    return destination


class AdapterError(RuntimeError):
    """The tool ran but could not produce a trustworthy result."""


class AdapterTimeout(AdapterError):
    """The tool exceeded its deadline and was killed."""


class AdapterCancelled(AdapterError):
    """The operator cancelled the job."""


class AdapterNotApplicable(AdapterError):
    """The target lacks the feature this adapter tests (nothing to assess).

    Distinct from a failure: the tool did not break, the capability simply does
    not apply to this target (no query parameters to vary, no API description
    served). The orchestrator records it as REJECTED coverage — still not a
    clean result, but not evidence that the scanner is broken either.
    """


@dataclass
class AdapterResult:
    """What one adapter observed, and whether it covered what it claims to.

    ``partial`` is the adapter's own admission that it checked less than its
    full capability (a deadline cut the sweep short, only some hosts answered,
    a port list hit its cap). An adapter that ran but reported partial coverage
    must never let the job claim complete coverage, so the orchestrator turns
    it into :attr:`ishastra.core.jobs.RunState.PARTIAL`.
    """

    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    partial: bool = False


class Adapter:
    """Base class: one capability, one tool, availability as it actually ran."""

    id: str = ""
    version: str = "0"
    asset_types: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Assess one target. ``context`` is the job-wide shared state: earlier
        adapters (the crawler) may publish discovered in-scope URLs there."""
        raise NotImplementedError

    def info(self) -> dict[str, Any]:
        ok, detail = self.available()
        return {
            "id": self.id,
            "version": self.version,
            "asset_types": list(self.asset_types),
            "requires": list(self.requires),
            "available": ok,
            "detail": detail,
        }

    def net_boundary_state(self) -> str:
        """Whether this adapter uses an enforceable network boundary.

        Override in adapters that install one so ``/api/adapters`` can report
        the current state without each adapter inventing its own vocabulary.
        """
        return "none"
