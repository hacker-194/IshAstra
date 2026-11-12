"""Regression tests for AuditChain caching behavior."""

from strix.audit import AuditChain


def test_verify_cached_rechecks_after_chain_is_fixed():
    """verify_cached should not keep stale failure results after the chain is repaired."""
    chain = AuditChain(hmac_key="test-secret")
    chain.append({"event": "test", "data": 1})
    chain.append({"event": "test", "data": 2})
    chain.append({"event": "test", "data": 3})

    assert chain.verify() == (True, None)

    chain._entries[1]["hash"] = "corrupted-hash-value"

    result1 = chain.verify_cached(max_age=30.0)
    assert result1[0] is False, "Corrupted chain should return False"
    assert "Hash mismatch" in result1[1]

    body = {k: v for k, v in chain._entries[1].items() if k != "hash"}
    correct_hash = chain._digest(body)
    chain._entries[1]["hash"] = correct_hash

    assert chain.verify() == (True, None), "Chain should be valid after fix"

    result2 = chain.verify_cached(max_age=30.0)

    assert result2 == (True, None), (
        "verify_cached should re-verify and not return stale cached failures after "
        "the chain is repaired"
    )


def test_verify_cached_respects_max_age():
    """
    Test that verify_cached re-verifies after max_age expires.

    This test shows the expected correct behavior - after max_age,
    verify_cached should re-verify and return the correct result.
    """
    chain = AuditChain(hmac_key="test-secret")
    chain.append({"event": "test", "data": 1})
    chain.append({"event": "test", "data": 2})

    # Corrupt the chain
    chain._entries[1]["hash"] = "corrupted"

    # First call - caches False
    result1 = chain.verify_cached(max_age=0.1)  # Very short cache
    assert result1[0] is False

    # Fix the chain
    body = {k: v for k, v in chain._entries[1].items() if k != "hash"}
    correct_hash = chain._digest(body)
    chain._entries[1]["hash"] = correct_hash

    # Wait for cache to expire
    import time

    time.sleep(0.2)

    # After max_age expires, should re-verify and return True
    result2 = chain.verify_cached(max_age=0.1)
    assert result2[0] is True, "Should re-verify after cache expires"
