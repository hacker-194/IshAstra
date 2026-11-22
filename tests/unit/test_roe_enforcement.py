"""Rules-of-engagement controls must be enforced, not just documented.

Two defects motivated these checks: an unparseable ``testing_hours`` schedule
was accepted at load time and then allowed every scan, and the advertised rate
limit / prohibited-technique controls were validated but never applied to an
adapter run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from ishastra.core.jobs import prohibited_technique_matches
from ishastra.core.probe import EndpointProbe
from ishastra.core.scope import Scope


def _scope(**roe) -> Scope:
    return Scope(
        program="p",
        authorized_by="a",
        authorization_ref="r",
        include=("example.com",),
        rules_of_engagement=roe,
    )


@pytest.mark.parametrize(
    "schedule",
    [
        "garbage",
        "09:00-18:00 America/New_York",
        "25:00-26:00 UTC",
        "09:00-18:00 UTC, Funday",
        "09:00-18:00 UTC, Mon-Fri, Sat",
    ],
)
def test_uneforceable_schedules_are_rejected_at_load(schedule: str) -> None:
    """A typo in the authorization document must not disable the control."""
    with pytest.raises(ValueError, match="testing_hours"):
        _scope(testing_hours=schedule)


def test_schedule_that_bypasses_validation_denies_the_gate() -> None:
    """Fail closed if a Scope is mutated after construction."""
    scope = _scope(testing_hours="09:00-18:00 UTC")
    object.__setattr__(scope, "rules_of_engagement", {"testing_hours": "midnight-ish"})

    denial, reason = scope._enforce_rules_of_engagement()

    assert denial == "roe_violation"
    assert "midnight-ish" in reason


def test_window_that_has_already_closed_denies_the_scan() -> None:
    now = datetime.now(UTC)
    start = (now - timedelta(minutes=31)).strftime("%H:%M")
    end = (now - timedelta(minutes=1)).strftime("%H:%M")
    scope = _scope(testing_hours=f"{start}-{end} UTC")

    assert scope._is_within_testing_hours(scope.rules_of_engagement["testing_hours"]) is False
    assert scope.check("https://example.com/")[0] == "roe_violation"


def test_whole_day_and_overnight_windows_are_enforceable() -> None:
    assert _scope(testing_hours="00:00-23:59 UTC")._is_within_testing_hours("00:00-23:59 UTC")
    # Overnight windows wrap rather than silently becoming an empty range.
    parsed = Scope._parse_testing_hours("22:00-06:00 UTC, Mon-Fri")
    assert parsed is not None
    assert parsed[0].hour == 22 and parsed[1].hour == 6


def test_prohibited_techniques_match_adapter_ids_and_tools() -> None:
    engagement = {"prohibited_techniques": [" SQLMap ", "brute-force"]}
    sqlmap_like = SimpleNamespace(id="sqlmap", requires=("sqlmap",))
    http_like = SimpleNamespace(id="ishastra-http", requires=())

    assert prohibited_technique_matches(engagement, sqlmap_like) == ["sqlmap"]
    assert prohibited_technique_matches(engagement, http_like) == []
    assert prohibited_technique_matches({}, sqlmap_like) == []


def test_prohibited_technique_can_name_the_underlying_binary() -> None:
    nuclei_like = SimpleNamespace(id="nuclei", requires=("nuclei",))
    assert prohibited_technique_matches({"prohibited_techniques": ["nuclei"]}, nuclei_like) == ["nuclei"]


def test_rate_limit_paces_in_process_probes() -> None:
    assert EndpointProbe(rate_limit_rps=4)._min_interval == pytest.approx(0.25)
    assert EndpointProbe()._min_interval == 0.0


def test_rate_limit_cannot_exceed_the_tool_ceiling() -> None:
    from ishastra.core.adapters import NucleiAdapter

    adapter = NucleiAdapter()
    assert adapter._rate_limit({"rate_limit_rps": 5}) == 5
    assert adapter._rate_limit({"rate_limit_rps": 10_000}) == adapter.RATE_LIMIT
    assert adapter._rate_limit(None) == adapter.RATE_LIMIT
