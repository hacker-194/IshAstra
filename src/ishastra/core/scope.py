"""Compatibility layer: scope authorization engine moved to security.authorization.

This module re-exports the public API from ishastra.security.authorization.scope
to maintain backward compatibility with existing imports.
"""

from __future__ import annotations

from ishastra.security.authorization.scope import *  # noqa: F403,F401
from ishastra.security.authorization.scope import (  # noqa: F401
    CURRENT_SCHEMA_VERSION,
    MAX_SUPPORTED_VERSION,
    MIN_SUPPORTED_VERSION,
    Destination,
    Scope,
    ValidationResult,
    _ambiguous,
    _host_pattern_error,
    active,
    bound,
    check,
    configure,
    configure_intel_from_env,
    configure_signing,
    current,
    destination,
    embedded_ipv4,
    extend_scope_expiry,
    get_pinned_destination,
    is_special_use,
    jit_url,
    load,
    parse_scope_document,
    register_intel,
    reset_observer,
    reset_pinned_destination,
    resolve,
    resolve_sync,
    revoke_scope,
    set_observer,
    set_pinned_destination,
    validate_scope_file,
)
