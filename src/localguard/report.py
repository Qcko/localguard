from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class SurfaceKind(str, Enum):
    OUTBOUND_NETWORK = "outbound_network"
    OUTBOUND_DYNAMIC = "outbound_dynamic"
    LISTENING_PORT = "listening_port"
    SUBPROCESS = "subprocess"
    FS_WRITE = "fs_write"
    ENV_SECRET_READ = "env_secret_read"
    HARDCODED_HOST = "hardcoded_host"
    TELEMETRY_ENDPOINT = "telemetry_endpoint"
    OBFUSCATION = "obfuscation"
    DATA_EXFIL_HINT = "data_exfil_hint"
    MCP_TOOL = "mcp_tool"
    MCP_RESOURCE = "mcp_resource"
    MCP_TRANSPORT_DRIFT = "mcp_transport_drift"
    PROMPT_INJECTION_HINT = "prompt_injection_hint"


class Confidence(str, Enum):
    LITERAL = "literal"
    TRACED = "local-var-traced"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    kind: SurfaceKind
    file: str
    line: int
    detail: str
    confidence: Confidence = Confidence.LITERAL
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreBreakdown:
    final_score: int
    deductions: list[dict[str, Any]] = field(default_factory=list)
    # Share of total deductions explained by surfaces the active profile
    # explicitly relaxes (i.e., "role-typical" findings). 0.0 means every
    # deduction is on a strict-by-design surface (suspicious); 1.0 means
    # every deduction is exactly what the role profile expects (likely
    # fine to manually accept). Computed by rubric.score.
    role_typical_share: float = 0.0


# Library entry status. Legacy reports written before this field exists
# are treated as `accepted` (the original semantics: presence in the
# library == user accepted).
class LibraryStatus(str, Enum):
    ACCEPTED = "accepted"
    # Blocked under the configured threshold, but >=80% of the deductions
    # land on surfaces the role profile relaxes. The findings are role-
    # typical and the package is most likely safe to manually accept.
    BLOCKED_ROLE_TYPICAL = "blocked-role-typical"
    # Blocked AND role-atypical deductions dominate -- the findings are
    # on strict-by-design surfaces. Manual review strongly recommended.
    BLOCKED_SUSPICIOUS = "blocked-suspicious"


@dataclass
class AuditReport:
    target: str
    target_hash: str
    findings: list[Finding] = field(default_factory=list)
    score: ScoreBreakdown | None = None
    ecosystem: str = "unknown"
    name: str | None = None
    version: str | None = None
    files_audited: int = 0
    profile: str = "plugin"
    profile_reason: str | None = None
    status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_hash": self.target_hash,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "files_audited": self.files_audited,
            "profile": self.profile,
            "profile_reason": self.profile_reason,
            "status": self.status,
            "score": asdict(self.score) if self.score else None,
            "findings": [_finding_to_dict(f) for f in self.findings],
        }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "kind": finding.kind.value,
        "file": finding.file,
        "line": finding.line,
        "detail": finding.detail,
        "confidence": finding.confidence.value,
        "extra": finding.extra,
    }
