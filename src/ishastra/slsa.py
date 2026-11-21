"""SLSA Provenance generation for Ishastra builds.

Generates SLSA Provenance (v1.0) attestations for supply chain security.
See https://slsa.dev/spec/v1.0/provenance
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class SlsaProvenance:
    """SLSA Provenance predicate (v1.0)."""

    buildDefinition: dict[str, Any] = field(default_factory=dict)
    runDetails: dict[str, Any] = field(default_factory=dict)


@dataclass
class BuildDefinition:
    """Build definition for SLSA provenance."""

    buildType: str = "https://github.com/ishastra/ishastra/builder@v1"
    externalParameters: dict[str, Any] = field(default_factory=dict)
    internalParameters: dict[str, Any] = field(default_factory=dict)
    resolvedDependencies: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RunDetails:
    """Run details for SLSA provenance."""

    builder: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    byproducts: list[dict[str, Any]] = field(default_factory=list)


def _get_git_info() -> dict[str, str]:
    """Extract git repository information."""
    info = {}
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["commit"] = result.stdout.strip()

        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["repo"] = result.stdout.strip()

        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["tag"] = result.stdout.strip()

        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["branch"] = result.stdout.strip()

    except Exception as e:
        log.debug("Failed to get git info: %s", e)

    return info


def _get_build_environment() -> dict[str, str]:
    """Get build environment information."""
    return {
        "os": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "builder": os.getenv("ISHASTRA_SLSA_BUILDER_ID", "local"),
        "build_started": os.getenv("ISHASTRA_BUILD_STARTED", str(int(time.time()))),
    }


def _hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Compute file hash."""
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return f"{algorithm}:{hasher.hexdigest()}"


def _collect_artifacts(output_dir: Path) -> list[dict[str, Any]]:
    """Collect build artifacts for provenance."""
    artifacts = []
    for path in output_dir.rglob("*"):
        if path.is_file():
            rel_path = path.relative_to(output_dir)
            artifacts.append(
                {
                    "name": str(rel_path),
                    "uri": f"file://{path}",
                    "hash": _hash_file(path),
                }
            )
    return artifacts


def _get_python_dependencies() -> list[dict[str, Any]]:
    """Get Python dependencies from pip."""
    deps = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            for pkg in packages:
                deps.append(
                    {
                        "name": pkg["name"],
                        "version": pkg["version"],
                        "hashes": [],
                    }
                )
    except Exception as e:
        log.debug("Failed to get Python dependencies: %s", e)
    return deps


def generate_slsa_provenance(
    output_dir: str | Path = "./provenance",
    builder_id: str | None = None,
    artifacts_dir: str | Path | None = None,
) -> Path:
    """Generate SLSA Provenance attestation.

    Args:
        output_dir: Directory to write provenance file
        builder_id: Builder identity URI (from config or env)
        artifacts_dir: Directory containing build artifacts to include

    Returns:
        Path to generated provenance file
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    git_info = _get_git_info()
    build_env = _get_build_environment()
    builder_id = builder_id or os.getenv("ISHASTRA_SLSA_BUILDER_ID", "local")

    build_def = BuildDefinition(
        buildType="https://github.com/ishastra/ishastra/builder@v1",
        externalParameters={
            "git": git_info,
            "environment": build_env,
        },
        internalParameters={
            "builder": builder_id,
        },
        resolvedDependencies=_get_python_dependencies(),
    )

    artifacts_dir = Path(artifacts_dir) if artifacts_dir else output_path
    byproducts = _collect_artifacts(artifacts_dir) if artifacts_dir.exists() else []

    run_details = RunDetails(
        builder={
            "id": builder_id,
            "version": "1.0.0",
        },
        metadata={
            "buildStartedOn": build_env["build_started"],
            "buildFinishedOn": str(int(time.time())),
            "completeness": {
                "parameters": True,
                "environment": True,
                "materials": True,
            },
            "reproducible": False,
        },
        byproducts=byproducts,
    )

    provenance = SlsaProvenance(
        buildDefinition=asdict(build_def),
        runDetails=asdict(run_details),
    )

    provenance_file = output_path / "slsa-provenance.json"
    with open(provenance_file, "w") as f:
        json.dump(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "ishastra",
                        "digest": {
                            "sha256": _hash_file(artifacts_dir / "ishastra")
                            if (artifacts_dir / "ishastra").exists()
                            else "placeholder",
                        },
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": asdict(provenance),
            },
            f,
            indent=2,
        )

    log.info("SLSA Provenance written to %s", provenance_file)
    return provenance_file


def verify_slsa_provenance(provenance_path: str | Path) -> bool:
    """Verify SLSA Provenance file structure.

    Args:
        provenance_path: Path to provenance file

    Returns:
        True if valid structure, False otherwise
    """
    try:
        with open(provenance_path) as f:
            data = json.load(f)

        required = ["_type", "subject", "predicateType", "predicate"]
        for field in required:
            if field not in data:
                log.error("Missing required field: %s", field)
                return False

        if data["_type"] != "https://in-toto.io/Statement/v1":
            log.error("Invalid _type: %s", data["_type"])
            return False

        if data["predicateType"] != "https://slsa.dev/provenance/v1":
            log.error("Invalid predicateType: %s", data["predicateType"])
            return False

        predicate = data["predicate"]
        if "buildDefinition" not in predicate or "runDetails" not in predicate:
            log.error("Missing buildDefinition or runDetails in predicate")
            return False

        return True
    except Exception as e:
        log.error("Failed to verify provenance: %s", e)
        return False


def main() -> int:
    """CLI entrypoint for SLSA provenance generation."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate SLSA Provenance for Ishastra")
    parser.add_argument(
        "-o",
        "--output",
        default="./provenance",
        help="Output directory for provenance file",
    )
    parser.add_argument(
        "-b",
        "--builder-id",
        help="Builder identity URI",
    )
    parser.add_argument(
        "-a",
        "--artifacts",
        help="Directory containing build artifacts",
    )
    parser.add_argument(
        "--verify",
        help="Verify a provenance file instead of generating",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.verify:
        if verify_slsa_provenance(args.verify):
            print("Provenance verification PASSED")
            return 0
        print("Provenance verification FAILED")
        return 1

    try:
        generate_slsa_provenance(
            output_dir=args.output,
            builder_id=args.builder_id,
            artifacts_dir=args.artifacts,
        )
        return 0
    except Exception as e:
        log.error("Failed to generate provenance: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
