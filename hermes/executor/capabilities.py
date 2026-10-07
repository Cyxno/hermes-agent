"""Capability registry (spec §24/§25).

Every mutating action Hermes can ever take is an explicit capability with a
risk level. FORBIDDEN capabilities exist in the registry so policy decisions
are auditable — they have no transport and can never execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..state.desired import MANAGED, OPTIONAL

SAFE = "SAFE"
GUARDED = "GUARDED"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
FORBIDDEN = "FORBIDDEN"


@dataclass(frozen=True)
class Capability:
    name: str
    description: str
    risk_level: str
    dispatch_action: str | None  # SSH operator-dispatch action; None = no transport
    allowed_lifecycle: tuple = (MANAGED, OPTIONAL)
    requires_approval: bool = False
    supports_rollback: bool = False
    timeout: float = 120.0
    verification: tuple = ("container_running",)
    extra_args: tuple = field(default=())


DEFAULT_CAPABILITIES: dict[str, Capability] = {
    cap.name: cap
    for cap in (
        Capability(
            "docker.restart", "Restart a known managed container", GUARDED,
            "docker-restart", verification=("container_running", "container_healthy"),
        ),
        Capability(
            "docker.start", "Start a stopped managed container", GUARDED,
            "docker-start", verification=("container_running", "container_healthy"),
        ),
        Capability(
            "docker.stop", "Stop a managed container (requires explicit reason)", APPROVAL_REQUIRED,
            "docker-stop", verification=("container_stopped",), requires_approval=True,
        ),
        Capability(
            "docker.recreate", "Force recreate of a compose service", FORBIDDEN,
            None, requires_approval=True,
        ),
        Capability(
            "compose.restart", "Restart an entire compose project", APPROVAL_REQUIRED,
            "docker-compose-restart", requires_approval=True,
        ),
        Capability(
            "service.restart", "Restart an allowlisted host service", GUARDED,
            "service-restart", verification=("service_running",),
        ),
        Capability("network.probe", "Basic network diagnostics (lossless, read-only)", SAFE, None,
                   verification=()),
        Capability("dns.probe", "DNS resolution check (read-only)", SAFE, None, verification=()),
        Capability("filesystem.inspect", "Filesystem status inspection (read-only)", SAFE, None,
                   verification=()),
        Capability("unraid.inspect", "Unraid array/system inspection (read-only)", SAFE, None,
                   verification=()),
        # Explicit forbidden classes — never executable, present for audit clarity.
        Capability("fs.delete_content", "Delete files", FORBIDDEN, None),
        Capability("disk.format", "Format a disk", FORBIDDEN, None),
        Capability("array.stop", "Stop the Unraid array", FORBIDDEN, None),
        Capability("hermes.self_modify", "Mutate Hermes own code/config", FORBIDDEN, None),
    )
}


class CapabilityRegistry:
    def __init__(self, overrides: dict | None = None) -> None:
        self._caps = dict(DEFAULT_CAPABILITIES)
        # config may only DOWNGRADE nothing; overrides may only tighten (rarely used)
        for name, extra in (overrides or {}).items():
            if name in self._caps and extra.get("require_approval") is True:
                base = self._caps[name]
                self._caps[name] = Capability(
                    **{**base.__dict__, "requires_approval": True, "risk_level": max(
                        (base.risk_level, "APPROVAL_REQUIRED"),
                        key=lambda r: (SAFE, GUARDED, APPROVAL_REQUIRED, FORBIDDEN).index(r),
                    )}
                )

    def get(self, name: str) -> Capability | None:
        return self._caps.get(name)

    def all(self) -> list[Capability]:
        return list(self._caps.values())
