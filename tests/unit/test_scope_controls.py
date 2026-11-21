"""ScopeGate controls map to requirements and cite the evidence that proves them."""

from __future__ import annotations

from ishastra.compliance.mapping import (
    SCOPE_CONTROLS,
    build_mapping_matrix,
    get_scope_control_matrix,
)


def test_every_scope_control_names_requirements_and_evidence():
    for name, control in SCOPE_CONTROLS.items():
        assert control["control"], name
        assert control["soc2"], name
        assert control["iso_27001"], name
        assert control["evidence"], name


def test_the_mapping_matrix_carries_the_scope_controls():
    matrix = build_mapping_matrix(["nrb"])

    assert matrix["scope_controls"] is SCOPE_CONTROLS
    assert get_scope_control_matrix()["total"] == len(SCOPE_CONTROLS) == 6
