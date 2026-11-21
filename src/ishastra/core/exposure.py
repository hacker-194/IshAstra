"""Native detection of an exposed git repository -- no external tool needed.

Fetches ``/.git/config`` and ``/.git/HEAD`` and accepts a response only when
its content has git's actual structure; a 200 serving an HTML shell (SPA
catch-all, generic error page) is not an exposure. The body is never stored --
only the structural markers that were found go into the evidence.
"""

from __future__ import annotations

import re
import threading
from typing import Any

from ishastra import __version__
from ishastra.core.adapter_base import (
    Adapter,
    AdapterCancelled,
    AdapterError,
    AdapterResult,
    AdapterTimeout,
    checked_destination,
)
from ishastra.core.findings import Finding
from ishastra.core.probe import EndpointProbe

_CONFIG_MARKERS = (
    re.compile(r"^\s*\[core\]\s*$", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*repositoryformatversion\s*=", re.MULTILINE | re.IGNORECASE),
)


_HTML_CATCHALL_PATTERNS = (
    re.compile(r"<!doctype\s+html>", re.IGNORECASE),
    re.compile(r"<html[^>]*>", re.IGNORECASE),
    re.compile(r"<head[^>]*>", re.IGNORECASE),
)


class GitExposureAdapter(Adapter):
    """Check whether the target exposes a .git directory."""

    id = "ishastra-git-exposure"
    version = __version__
    asset_types = ("web", "api")
    requires = ()

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    @staticmethod
    def _is_html_catchall(body: str) -> bool:
        return any(p.search(body) for p in _HTML_CATCHALL_PATTERNS)

    @staticmethod
    def _is_config(body: str) -> bool:
        return all(p.search(body) for p in _CONFIG_MARKERS)

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        result = AdapterResult()

        try:
            probe = EndpointProbe(timeout=timeout, max_body=65536)
            config_url = f"{destination.scheme}://{destination.host}:{destination.port}/.git/config"
            probe_response = probe._fetch(config_url, timeout=timeout)
            status = probe_response.get("status")
            if status != 200:
                if status == "error" or status == "timeout":
                    result.partial = True
                    result.notes.append("request failed; exposure could not be ruled out")
                else:
                    result.notes.append(f"no exposed git metadata ({status})")
                return result

            body = probe_response.get("body", "")
            if self._is_html_catchall(body):
                result.notes.append("no exposed git metadata (HTML catch-all)")
                return result

            if not self._is_config(body):
                result.notes.append("no exposed git metadata (not a git config)")
                return result

            head_url = f"{destination.scheme}://{destination.host}:{destination.port}/.git/HEAD"
            head_response = probe._fetch(head_url, timeout=timeout)
            head_status = head_response.get("status")
            if head_status != 200:
                if head_status in ("error", "timeout"):
                    result.partial = True
                    result.notes.append("request failed; exposure could not be ruled out")
                else:
                    result.notes.append("git config present but HEAD missing")
                    result.partial = True
                return result

            head_body = head_response.get("body", "")
            if not re.search(r"^ref:\s*refs/heads/", head_body, re.MULTILINE):
                result.notes.append("git config present but HEAD malformed")
                result.partial = True
                return result

            result.findings.append(
                Finding(
                    asset=target,
                    category="git_config_exposed",
                    title="Exposed Git Repository",
                    severity="high",
                    confidence="high",
                    detector=self.id,
                    detector_version=self.version,
                    evidence="markers present: [core], repositoryformatversion",
                    location=config_url,
                    description="The target exposes a .git directory allowing full source code disclosure.",
                    verification="observed",
                )
            )
            return result

        except AdapterCancelled:
            raise
        except AdapterTimeout:
            result.partial = True
            result.notes.append("request timed out; exposure could not be ruled out")
            return result
        except AdapterError as exc:
            result.notes.append(str(exc))
            result.partial = True
            return result
