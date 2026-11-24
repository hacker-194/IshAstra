"""Regression tests for the readiness drill helpers."""

from __future__ import annotations

import re

from scripts.readiness_check import generate_hmac_key


def test_hmac_key_is_argparse_safe() -> None:
    key = generate_hmac_key()
    # Hex never starts with "-"; a urlsafe token occasionally does.
    assert re.fullmatch(r"[0-9a-f]{64}", key)
    assert not key.startswith("-")
