"""Evidence Signing Service.

Called by:
- src/ishastra/execution/worker_manager.py (imports EvidenceSigningService)
- src/ishastra/control_plane/dispatcher.py (imports EvidenceSigningService)
- src/ishastra/cli.py (imports verify_evidence_file)
- Tests in tests/unit/test_evidence_signing.py

Re-exports signing module for v4.0 security spine.
"""
