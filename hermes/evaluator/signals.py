"""Signals: normalized evidence-derived candidates produced by deterministic rules."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"notice": 0, "warning": 1, "urgent": 2, "critical": 3, "recovery": -1}

# Signal categories that are always urgent-to-critical and effectively immediate.
IMMEDIATE_CATEGORIES = frozenset(
    {"filesystem_readonly", "disk_missing", "array_parity_fault", "host_unreachable"}
)


@dataclass
class Signal:
    category: str
    entity: str
    severity: str  # notice|warning|urgent|critical | recovery
    source: str  # beacon|netdata|fallback|derived
    ts: float
    value: float | None = None
    title: str | None = None
    evidence: list[dict] = field(default_factory=list)
    cleared: bool = False  # explicit recovery for band-based metrics
    kind: str = "condition"  # condition | recovery | event

    @property
    def fingerprint(self) -> str:
        return f"{self.category}:{self.entity}"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def confirm_sources(self) -> set[str]:
        """Distinct sources that currently confirm the condition (spec §4)."""
        return {e.get("source", self.source) for e in self.evidence if e.get("confirm")}

    def describe(self) -> str:
        if self.title:
            return self.title
        value = f" (waarde: {self.value})" if self.value is not None else ""
        return f"{self.category} op {self.entity}{value}"


@dataclass
class NotificationIntent:
    incident_id: str
    kind: str  # alert | escalation | resolved | pattern
    severity: str
    title: str
    body: str
    ts: float
