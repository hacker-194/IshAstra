"""Egress Gateway - CONNECT/SOCKS5 proxy with capability enforcement.

Called by:
- src/ishastra/execution/worker_manager.py (imports EgressGateway)
- src/ishastra/control_plane/dispatcher.py (imports EgressGateway)
- Tests in tests/unit/test_egress_gateway.py

Re-exports gateway module for v4.0 security spine.
"""
