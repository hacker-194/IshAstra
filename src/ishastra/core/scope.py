"""Compatibility layer: scope authorization engine moved to security.authorization.

This module re-exports the public API from ishastra.security.authorization.scope
to maintain backward compatibility with existing imports.
"""

from __future__ import annotations

from ishastra.security.authorization.scope import *  # noqa: F403,F401

# Explicit re-exports for type checkers (includes internal functions used by tests)
from ishastra.security.authorization.scope import (  # noqa: F401
    ValidationResult,
    Destination,
    Scope,
    check,
    destination,
    configure,
    load,
    bound,
    current,
    configure_signing,
    configure_intel_from_env,
    jit_url,
    register_intel,
    CURRENT_SCHEMA_VERSION,
    MIN_SUPPORTED_VERSION,
    MAX_SUPPORTED_VERSION,
    set_pinned_destination,
    reset_pinned_destination,
    get_pinned_destination,
    active,
    parse_scope_document,
    _ambiguous,
    _host_pattern_error,
    embedded_ipv4,
    is_special_use,
    resolve,
    resolve_sync,
    set_observer,
    reset_observer,
    extend_scope_expiry,
    revoke_scope,
    validate_scope_file,
)