"""Host firewall plan for the worker network.

The egress gateway is the primary control: a worker can only reach an
authorized destination by presenting a capability token. This module is the
secondary control, so a worker that ignores the proxy still cannot reach
anything except the gateway port.

The plan is deny-by-default for the worker subnet:

- established/related traffic is accepted;
- worker subnet -> gateway_ip:gateway_port TCP is accepted;
- everything else from the worker subnet is dropped;
- cloud metadata addresses are dropped explicitly (defense in depth).

Generating and validating the rules is tested. Applying them needs root and
nftables and is **not verified** in environments without those, see
docs/architecture/EGRESS_ENFORCEMENT.md.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

TABLE_NAME = "ishastra_egress"
CHAIN_NAME = "worker_egress"

METADATA_ADDRESSES = (
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
)


@dataclass(frozen=True)
class FirewallPlan:
    """One worker network and the single gateway it may reach."""

    worker_subnet: str
    gateway_ip: str
    gateway_port: int

    def __post_init__(self) -> None:
        network = ipaddress.ip_network(self.worker_subnet, strict=False)
        gateway = ipaddress.ip_address(self.gateway_ip)
        if network.prefixlen == 0:
            raise ValueError("worker_subnet must not be 0.0.0.0/0 or ::/0")
        if network.version != gateway.version:
            raise ValueError("worker_subnet and gateway_ip must share an address family")
        if not 1 <= self.gateway_port <= 65535:
            raise ValueError("gateway_port must be between 1 and 65535")
        if str(gateway) in METADATA_ADDRESSES:
            raise ValueError("gateway_ip must not be a cloud metadata address")
        object.__setattr__(self, "worker_subnet", str(network))
        object.__setattr__(self, "gateway_ip", str(gateway))

    @property
    def selector(self) -> str:
        """nft address selector for this family."""
        return "ip6" if ":" in self.worker_subnet else "ip"


@dataclass(frozen=True)
class FirewallResult:
    """Outcome of an apply attempt."""

    applied: bool
    reason: str
    commands: tuple[str, ...] = ()


def _is_root() -> bool | None:
    """True/False on POSIX; None where the platform has no euid concept."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return None
    return geteuid() == 0


def render_nft_script(plan: FirewallPlan) -> str:
    """Full nftables script, applied atomically with ``nft -f``.

    ``policy accept`` on the forward hook keeps unrelated traffic working; the
    worker subnet is isolated by the accept-then-drop pair, in that order.
    """
    sel = plan.selector
    lines = [
        f"table inet {TABLE_NAME} {{",
        f"  chain {CHAIN_NAME} {{",
        "    type filter hook forward priority -10; policy accept;",
        "    ct state established,related accept",
        (
            f"    {sel} saddr {plan.worker_subnet} "
            f"{sel} daddr {plan.gateway_ip} "
            f"tcp dport {plan.gateway_port} accept"
        ),
    ]
    for address in METADATA_ADDRESSES:
        is_v4 = ipaddress.ip_address(address).version == 4
        if is_v4 == (sel == "ip"):
            lines.append(f"    {sel} daddr {address} drop")
    lines.extend(
        [
            f"    {sel} saddr {plan.worker_subnet} drop",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_teardown_script() -> str:
    """Idempotent removal of the table this module creates."""
    return f"delete table inet {TABLE_NAME}\n"


def docker_user_commands(plan: FirewallPlan) -> tuple[tuple[str, ...], ...]:
    """DOCKER-USER fallback, in order: accept the gateway, then drop the rest.

    Uses ``-A`` and assumes the chain is otherwise empty, so the accept rule is
    evaluated before the drop. ``nftables`` via ``-I DOCKER-USER 1`` would
    invert that order and silently allow nothing.
    """
    return (
        (
            "iptables",
            "-A",
            "DOCKER-USER",
            "-s",
            plan.worker_subnet,
            "-d",
            plan.gateway_ip,
            "-p",
            "tcp",
            "--dport",
            str(plan.gateway_port),
            "-j",
            "ACCEPT",
        ),
        ("iptables", "-A", "DOCKER-USER", "-s", plan.worker_subnet, "-j", "DROP"),
    )


def apply(plan: FirewallPlan, *, dry_run: bool = False) -> FirewallResult:
    """Apply the plan with ``nft -f``. Never uses a shell."""
    script = render_nft_script(plan)
    if dry_run:
        return FirewallResult(True, "dry run: rules were not applied", (script,))
    if os.name == "nt":
        return FirewallResult(
            False, "nftables is Linux-only; apply the plan on a Linux host", ()
        )
    root = _is_root()
    if root is None:
        return FirewallResult(False, "this platform has no POSIX euid; cannot apply", ())
    if not root:
        return FirewallResult(False, "root is required to apply nftables rules", ())
    nft = shutil.which("nft")
    if nft is None:
        return FirewallResult(False, "nft is not installed", ())

    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as handle:
        handle.write(script)
        path = Path(handle.name)
    try:
        path.chmod(0o600)
        completed = subprocess.run(
            [nft, "-f", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return FirewallResult(False, f"nft failed: {exc}", ())
    finally:
        path.unlink(missing_ok=True)

    if completed.returncode != 0:
        return FirewallResult(False, completed.stderr.strip() or "nft returned non-zero", ())
    return FirewallResult(True, "rules applied", (script,))
