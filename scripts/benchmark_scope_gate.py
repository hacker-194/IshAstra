"""Load test for the scope gate: measure it, do not guess.

    python3 scripts/benchmark_scope_gate.py --requests 20000

The resolver is stubbed so the numbers are the gate's own cost rather than DNS
latency. No dependencies; prints ops/s and p50/p95/p99 latency per entry point.
"""

from __future__ import annotations

import argparse
import time

from ishastra.core import scope as scope_module

ADDRESS = "93.184.216.34"
URL = "https://example.com/login"


def _measure(call, count: int) -> dict[str, float]:
    samples: list[float] = []
    started = time.perf_counter()
    for _ in range(count):
        at = time.perf_counter()
        call()
        samples.append(time.perf_counter() - at)
    elapsed = time.perf_counter() - started
    samples.sort()

    def percentile(fraction: float) -> float:
        index = min(len(samples) - 1, int(len(samples) * fraction))
        return samples[index] * 1e3

    return {
        "ops/s": count / elapsed,
        "p50_ms": percentile(0.5),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "max_ms": samples[-1] * 1e3,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure the scope gate's own latency.")
    parser.add_argument("--requests", type=int, default=20000)
    args = parser.parse_args()

    scope_module.resolve_sync = lambda host, port=None: [ADDRESS]
    scope_module._host_buckets.clear()
    gate = scope_module.Scope(
        program="Load",
        authorized_by="Benchmark",
        authorization_ref="LOAD-1",
        include=("example.com",),
        authorized_networks=("93.184.216.0/24",),
        allowed_ports=(443,),
    )
    assert gate.check(URL)[0] == "", "the benchmark scope must allow its own target"

    for label, call in (
        ("check", lambda: gate.check(URL)),
        ("destination", lambda: gate.destination(URL)),
    ):
        stats = _measure(call, args.requests)
        rendered = "  ".join(f"{key}={value:,.1f}" for key, value in stats.items())
        print(f"{label:12} {rendered}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
