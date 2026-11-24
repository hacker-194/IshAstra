#!/usr/bin/env python3
"""Write an SPDX 2.3 SBOM for the installed distribution set.

Standard library only: the release job already installs the package, so
this needs no extra toolchain or network access to describe the artifact.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path


def build_sbom(name: str = "ishastra") -> dict:
    packages = []
    seen: set[tuple[str, str]] = set()
    for dist in metadata.distributions():
        pkg_name = (dist.metadata["Name"] or "").strip()
        pkg_version = (dist.version or "").strip()
        if not pkg_name or (pkg_name.lower(), pkg_version) in seen:
            continue
        seen.add((pkg_name.lower(), pkg_version))
        declared = (dist.metadata.get("License") or "").strip() or "NOASSERTION"
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{pkg_name}-{pkg_version}".replace(" ", "-"),
                "name": pkg_name,
                "versionInfo": pkg_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": declared.replace("\n", " ")[:200],
                "supplier": "NOASSERTION",
            }
        )
    packages.sort(key=lambda pkg: (pkg["name"].lower(), pkg["versionInfo"]))
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-sbom",
        "documentNamespace": f"https://ishastra.dev/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(UTC).isoformat(timespec="seconds"),
            "creators": ["Tool: ishastra-sbom"],
        },
        "packages": packages,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate an SPDX SBOM for the installed packages")
    parser.add_argument("--output", "-o", default="sbom.spdx.json", help="Output file")
    parser.add_argument("--name", default="ishastra", help="Document name prefix")
    args = parser.parse_args(argv)

    document = build_sbom(args.name)
    Path(args.output).write_text(json.dumps(document, indent=2) + "\n")
    print(f"SBOM written to {args.output} ({len(document['packages'])} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
