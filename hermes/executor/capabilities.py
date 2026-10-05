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
            "docker.restart", "Herstart een bekende managed container", GUARDED,
            "docker-restart", verification=("container_running", "container_healthy"),
        ),
        Capability(
            "docker.start", "Start een gestopte managed container", GUARDED,
            "docker-start", verification=("container_running", "container_healthy"),
        ),
        Capability(
            "docker.stop", "Stopt een managed container (alleen met duidelijke reden)", GUARDED,
            "docker-stop", verification=("container_stopped",), requires_approval=False,
        ),
        Capability(
            "docker.recreate", "Forceer recreate van een compose-service", FORBIDDEN,
            None, requires_approval=True,
        ),
        Capability(
            "compose.restart", "Herstart een heel compose-project", APPROVAL_REQUIRED,
            "docker-compose-restart", requires_approval=True,
        ),
        Capability(
            "service.restart", "Herstart een allowlisted host-service", GUARDED,
            "service-restart", verification=("service_running",),
        ),
        Capability("network.probe", "Basis netwerkdiagnose (lossless, read-only)", SAFE, None,
                   verification=()),
        Capability("dns.probe", "DNS-resolutie controle (read-only)", SAFE, None, verification=()),
        Capability("filesystem.inspect", "Filesystem status inspectie (read-only)", SAFE, None,
                   verification=()),
        Capability("unraid.inspect", "Unraid array/system inspectie (read-only)", SAFE, None,
                   verification=()),
        # Explicit forbidden classes — never executable, present for audit clarity.
        Capability("fs.delete_content", "Verwijderen van bestanden", FORBIDDEN, None),
        Capability("disk.format", "Een schijf formatteren", FORBIDDEN, None),
        Capability("array.stop", "De Unraid-array stoppen", FORBIDDEN, None),
        Capability("hermes.self_modify", "Hermes eigen code/config muteren", FORBIDDEN, None),
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
