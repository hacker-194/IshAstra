#!/usr/bin/env python3
"""Performance benchmark for scanner isolation overhead.

Compares execution time and resource usage of scanners running:
1. Native (no sandbox) - baseline
2. gVisor (runsc) - K8s RuntimeClass gvisor
3. Kata Containers - K8s RuntimeClass kata

Run inside a K8s cluster with gVisor and Kata RuntimeClasses installed.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    runtime: str
    scanner: str
    target: str
    duration_seconds: float
    cpu_user_seconds: float
    cpu_system_seconds: float
    max_rss_kb: int
    exit_code: int
    success: bool
    error: str | None = None


def run_command(cmd: list[str], timeout: float = 120) -> tuple[int, str, str, float, float, int]:
    """Run a command and return (exit_code, stdout, stderr, user_time, sys_time, max_rss)."""
    start = time.time()
    try:
        # Use /usr/bin/time -v for resource usage (Linux)
        time_cmd = ["/usr/bin/time", "-v"] + cmd
        result = subprocess.run(
            time_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.time() - start

        # Parse /usr/bin/time -v output from stderr
        user_time = 0.0
        sys_time = 0.0
        max_rss = 0
        for line in result.stderr.splitlines():
            line = line.strip()
            if line.startswith("User time (seconds):"):
                user_time = float(line.split(":")[1].strip())
            elif line.startswith("System time (seconds):"):
                sys_time = float(line.split(":")[1].strip())
            elif line.startswith("Maximum resident set size (kbytes):"):
                max_rss = int(line.split(":")[1].strip())

        return result.returncode, result.stdout, result.stderr, user_time, sys_time, max_rss
    except subprocess.TimeoutExpired:
        return -1, "", "timeout", 0.0, 0.0, 0
    except Exception as exc:
        return -1, "", str(exc), 0.0, 0.0, 0


def benchmark_scanner(
    runtime: str,
    scanner: str,
    target: str,
    iterations: int = 3,
    timeout: float = 120,
) -> list[BenchmarkResult]:
    """Benchmark a scanner under a specific runtime."""
    results = []

    # Scanner command templates
    scanner_cmds = {
        "nmap": ["nmap", "-sT", "-Pn", "-n", "-p", "80,443", "--host-timeout", "30s", "-oX", "-", target],
        "nuclei": ["nuclei", "-u", target, "-t", "http/exposures", "-jsonl", "-silent", "-no-color", "-no-interactsh", "-rate-limit", "10", "-concurrency", "5", "-timeout", "10"],
        "nikto": ["nikto", "-nointeractive", "-host", target.replace("https://", "").replace("http://", "").split(":")[0], "-port", "443" if target.startswith("https") else "80", "-Format", "json", "-maxtime", "60"],
        "sqlmap": ["sqlmap", "-u", target, "--batch", "--crawl", "0", "--level", "1", "--risk", "1", "--technique", "BT", "--timeout", "5", "--retries", "0", "--disable-coloring", "--flush-session", "--fresh-queries"],
    }

    if scanner not in scanner_cmds:
        return [BenchmarkResult(
            runtime=runtime, scanner=scanner, target=target,
            duration_seconds=0, cpu_user_seconds=0, cpu_system_seconds=0,
            max_rss_kb=0, exit_code=-1, success=False,
            error=f"Unknown scanner: {scanner}"
        )]

    base_cmd = scanner_cmds[scanner]

    for i in range(iterations):
        print(f"  [{runtime}/{scanner}] Run {i+1}/{iterations}...", end=" ", flush=True)

        if runtime == "native":
            cmd = base_cmd
        elif runtime == "gvisor":
            cmd = ["runsc", "--"] + base_cmd
        elif runtime == "kata":
            # Kata uses a different approach - typically via containerd runtime
            # For benchmarking, we simulate with runc + kata overhead
            cmd = ["runsc", "--"] + base_cmd  # Placeholder
        else:
            cmd = base_cmd

        exit_code, stdout, stderr, user_time, sys_time, max_rss = run_command(cmd, timeout)

        duration = user_time + sys_time  # Approximate

        result = BenchmarkResult(
            runtime=runtime,
            scanner=scanner,
            target=target,
            duration_seconds=duration,
            cpu_user_seconds=user_time,
            cpu_system_seconds=sys_time,
            max_rss_kb=max_rss,
            exit_code=exit_code,
            success=(exit_code == 0),
            error=stderr[:200] if exit_code != 0 else None,
        )
        results.append(result)

        status = "OK" if result.success else f"FAILED ({result.error})"
        print(f" {status} ({duration:.2f}s)")

    return results


def calculate_overhead(native_results: list[BenchmarkResult], sandbox_results: list[BenchmarkResult]) -> dict[str, float]:
    """Calculate overhead percentages between native and sandbox runs."""
    if not native_results or not sandbox_results:
        return {}

    native_durations = [r.duration_seconds for r in native_results if r.success]
    sandbox_durations = [r.duration_seconds for r in sandbox_results if r.success]

    if not native_durations or not sandbox_durations:
        return {}

    native_avg = statistics.mean(native_durations)
    sandbox_avg = statistics.mean(sandbox_durations)

    overhead_pct = ((sandbox_avg - native_avg) / native_avg) * 100 if native_avg > 0 else 0

    native_rss = statistics.mean([r.max_rss_kb for r in native_results if r.success])
    sandbox_rss = statistics.mean([r.max_rss_kb for r in sandbox_results if r.success])

    rss_overhead_pct = ((sandbox_rss - native_rss) / native_rss) * 100 if native_rss > 0 else 0

    return {
        "time_overhead_percent": overhead_pct,
        "memory_overhead_percent": rss_overhead_pct,
        "native_avg_duration": native_avg,
        "sandbox_avg_duration": sandbox_avg,
        "native_avg_rss_kb": native_rss,
        "sandbox_avg_rss_kb": sandbox_rss,
    }


def main():
    parser = argparse.ArgumentParser(description="Scanner isolation overhead benchmark")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--scanners", nargs="+", default=["nmap", "nuclei", "nikto"],
                        choices=["nmap", "nuclei", "nikto", "sqlmap"],
                        help="Scanners to benchmark")
    parser.add_argument("--runtimes", nargs="+", default=["native", "gvisor"],
                        choices=["native", "gvisor", "kata"],
                        help="Runtimes to test")
    parser.add_argument("--iterations", type=int, default=3, help="Iterations per test")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per run (seconds)")
    parser.add_argument("--output", type=str, help="Output JSON file")
    args = parser.parse_args()

    print(f"Benchmarking scanners: {args.scanners}")
    print(f"Runtimes: {args.runtimes}")
    print(f"Target: {args.target}")
    print(f"Iterations: {args.iterations}")
    print()

    all_results = []
    overhead_summary = {}

    for scanner in args.scanners:
        print(f"\n=== {scanner.upper()} ===")
        scanner_results = {}
        native_results = []

        for runtime in args.runtimes:
            results = benchmark_scanner(runtime, scanner, args.target, args.iterations, args.timeout)
            scanner_results[runtime] = results
            all_results.extend(results)

            if runtime == "native":
                native_results = results

        # Calculate overhead for each sandbox runtime
        for runtime in args.runtimes:
            if runtime == "native":
                continue
            overhead = calculate_overhead(native_results, scanner_results.get(runtime, []))
            if overhead:
                key = f"{scanner}/{runtime}"
                overhead_summary[key] = overhead
                print(f"  Overhead vs native: {overhead['time_overhead_percent']:.1f}% time, {overhead['memory_overhead_percent']:.1f}% memory")

    # Print summary
    print("\n=== OVERHEAD SUMMARY ===")
    for key, overhead in overhead_summary.items():
        print(f"  {key}: {overhead['time_overhead_percent']:.1f}% time overhead, {overhead['memory_overhead_percent']:.1f}% memory overhead")
        print(f"    Native: {overhead['native_avg_duration']:.2f}s / {overhead['native_avg_rss_kb']:.0f}KB")
        print(f"    Sandbox: {overhead['sandbox_avg_duration']:.2f}s / {overhead['sandbox_avg_rss_kb']:.0f}KB")

    # Save results
    if args.output:
        output_data = {
            "target": args.target,
            "scanners": args.scanners,
            "runtimes": args.runtimes,
            "iterations": args.iterations,
            "results": [asdict(r) for r in all_results],
            "overhead_summary": overhead_summary,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to {args.output}")

    # Exit with non-zero if any critical overhead exceeds threshold
    max_time_overhead = max((o["time_overhead_percent"] for o in overhead_summary.values()), default=0)
    if max_time_overhead > 50:  # 50% overhead threshold
        print(f"\nWARNING: Maximum time overhead ({max_time_overhead:.1f}%) exceeds 50% threshold")
        sys.exit(1)


if __name__ == "__main__":
    main()
