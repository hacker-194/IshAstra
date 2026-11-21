"""Public proof verification: check a Ishastra Proof pack, trusting nothing.

Deliberately unauthenticated -- a client, auditor or insurer must be able to
verify a pack without an account -- and therefore stateless: the pack is never
stored or echoed back, and nothing in it authorizes anything.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ishastra import proof
from ishastra.core.redaction import redact_text

router = APIRouter(prefix="/api")


MAX_REPORTED_ERRORS = 20
MAX_ERROR_CHARS = 500


class VerifyRequest(BaseModel):
    proof: dict[str, Any] = Field(..., description="The proof pack JSON")
    trusted_issuer: str = Field(default="", max_length=128, description="Pin the issuer public key")
    trusted_gate: str = Field(default="", max_length=128, description="Pin the gate public key")


@router.post("/proof/verify")
def verify_proof(req: VerifyRequest) -> dict[str, Any]:
    """Verify a proof pack offline-equivalently: no signature is taken on trust."""
    report = proof.verify_pack(
        req.proof,
        trusted_issuer=req.trusted_issuer or None,
        trusted_gate=req.trusted_gate or None,
    )
    return {
        **report,
        "errors": [
            redact_text(str(error))[:MAX_ERROR_CHARS] for error in report["errors"][:MAX_REPORTED_ERRORS]
        ],
        "verified_at": time.time(),
    }
