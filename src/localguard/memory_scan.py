"""Static injection scan for trusted-content blobs.

The approval-time gate for server-shipped memory and other free text that a
consumer (e.g. GLaDOS) wants to inject into an LLM's trusted prompt. This
module answers "what does this blob *look* like?" -- it never decides trust.
The human (via `localguard memory approve`) decides; load-time trust is a
pure hash lookup against the approved baseline (see memory_store).

The scan reuses the package-audit text sweep (URLs, IPs, env secrets, base64
blobs) and layers the prompt-injection-specific signals on top: role-tag
spoofing, instruction-override phrases, auto-confirm directives, exfil hints,
zero-width / bidi obfuscation, defanged framing tags, and length anomalies.
"""

from __future__ import annotations

import re
from pathlib import Path

from .mcp_detector import PROMPT_INJECTION_PATTERN, ZERO_WIDTH
from .report import Confidence, Finding, SurfaceKind
from .text_sweep import sweep_text
from .walker import SourceFile


MEMORY_REL = "<memory>"

# Severity split. Unlike a package (where a "role profile" relaxes expected
# surfaces), trusted text has no legitimate reason to carry injection / exfil /
# obfuscation -- those are inherently adverse. A bare embedded URL, by
# contrast, may be a legitimate citation, so it is only informational.
ADVERSE_KINDS = {
    SurfaceKind.PROMPT_INJECTION_HINT,
    SurfaceKind.DATA_EXFIL_HINT,
    SurfaceKind.OBFUSCATION,
    SurfaceKind.TELEMETRY_ENDPOINT,
    SurfaceKind.ENV_SECRET_READ,
}

# Chat-format role tags at the start of a line: a memory blob that opens a
# turn boundary is trying to escape its <memory-notes> framing.
ROLE_TAG_PATTERN = re.compile(r"^\s*(system|assistant|user|developer|tool)\s*[:\-]", re.IGNORECASE | re.MULTILINE)

# Instruction-override phrases not already covered by PROMPT_INJECTION_PATTERN.
OVERRIDE_PATTERN = re.compile(
    r"(you\s+are\s+now|new\s+instructions?\s*[:\-]|override\s+(?:the\s+)?(?:above|previous|system)|"
    r"from\s+now\s+on\s+you)",
    re.IGNORECASE,
)

# Directives that try to suppress the human-in-the-loop the consumer relies on.
AUTO_CONFIRM_PATTERN = re.compile(
    r"(auto[\s\-]?(?:approve|confirm)|automatically\s+(?:approve|confirm|run)|"
    r"without\s+(?:asking|confirmation)|do\s+not\s+ask|always\s+(?:say\s+yes|confirm|approve)|"
    r"skip\s+(?:the\s+)?confirmation)",
    re.IGNORECASE,
)

# Exfil hints: phrasing that asks the model to ship data outward. Bare URLs
# are already caught by the text sweep; this catches the *instruction* to send.
EXFIL_PATTERN = re.compile(
    r"(include\s+the\s+following|send\s+(?:it|this|the\s+\w+)\s+to|exfiltrat|"
    r"POST\s+(?:it|this|the)|forward\s+(?:this|the)\s+\w+\s+to|webhook)",
    re.IGNORECASE,
)

# Framing tags the consumer uses to delimit untrusted content. A blob that
# contains them verbatim is trying to close/forge the delimiter (defang).
FRAMING_TAG_PATTERN = re.compile(r"</?(?:external|system|memory-notes|untrusted-content|trusted)\s*>", re.IGNORECASE)

# Anomaly caps. A memory blob is domain lessons, not a novel; oversized blobs
# or pathologically long single lines are smuggling something.
MAX_BLOB_CHARS = 8_000
MAX_LINE_CHARS = 600


def scan_memory(blob: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_sweep_via_text_layer(blob))
    findings.extend(_find_role_tags(blob))
    findings.extend(_find_injection_phrases(blob))
    findings.extend(_find_auto_confirm(blob))
    findings.extend(_find_exfil(blob))
    findings.extend(_find_framing_tags(blob))
    findings.extend(_find_obfuscation(blob))
    findings.extend(_find_anomalies(blob))
    return findings


def severity_of(kind: SurfaceKind) -> str:
    return "adverse" if kind in ADVERSE_KINDS else "informational"


def summarize(findings: list[Finding]) -> dict:
    """Group findings by severity and derive a human recommendation.

    `level` is one of: clean (no findings), caution (only informational), or
    review (any adverse finding). The recommendation is advisory -- the human
    gate, not this label, decides whether the blob is approved.
    """
    adverse = [f for f in findings if severity_of(f.kind) == "adverse"]
    informational = [f for f in findings if severity_of(f.kind) != "adverse"]
    if not findings:
        level = "clean"
        message = "no injection signals detected; safe to approve"
    elif adverse:
        kinds = ", ".join(sorted({f.kind.value for f in adverse}))
        level = "review"
        message = f"{len(adverse)} adverse signal(s) ({kinds}); approve ONLY if you wrote or expected this exact text"
    else:
        level = "caution"
        message = f"{len(informational)} informational finding(s) (e.g. embedded URL); verify they are legitimate references before approving"
    return {"level": level, "message": message, "adverse": adverse, "informational": informational}


def _sweep_via_text_layer(blob: str) -> list[Finding]:
    """Reuse the package-audit text sweep (URLs, IPs, env secrets, base64).

    A memory blob is plain text, so every line is "code" to the sweep -- no
    comment/docstring suppression, which is exactly what we want here.
    """
    source = SourceFile(path=Path(MEMORY_REL), rel=MEMORY_REL, language="text", text=blob)
    return sweep_text(source)


def _find_role_tags(blob: str) -> list[Finding]:
    return _findings_for(blob, ROLE_TAG_PATTERN, SurfaceKind.PROMPT_INJECTION_HINT, "role-tag")


def _find_injection_phrases(blob: str) -> list[Finding]:
    findings = _findings_for(blob, PROMPT_INJECTION_PATTERN, SurfaceKind.PROMPT_INJECTION_HINT, "instruction-override")
    findings.extend(_findings_for(blob, OVERRIDE_PATTERN, SurfaceKind.PROMPT_INJECTION_HINT, "instruction-override"))
    return findings


def _find_auto_confirm(blob: str) -> list[Finding]:
    return _findings_for(blob, AUTO_CONFIRM_PATTERN, SurfaceKind.PROMPT_INJECTION_HINT, "auto-confirm-directive")


def _find_exfil(blob: str) -> list[Finding]:
    return _findings_for(blob, EXFIL_PATTERN, SurfaceKind.DATA_EXFIL_HINT, "exfil-phrase")


def _find_framing_tags(blob: str) -> list[Finding]:
    return _findings_for(blob, FRAMING_TAG_PATTERN, SurfaceKind.PROMPT_INJECTION_HINT, "framing-tag")


def _find_obfuscation(blob: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(blob.splitlines(), start=1):
        if ZERO_WIDTH.search(line):
            findings.append(_finding(line_no, "<zero-width / bidi-override chars>", SurfaceKind.OBFUSCATION, "zero-width"))
    return findings


def _find_anomalies(blob: str) -> list[Finding]:
    findings: list[Finding] = []
    if len(blob) > MAX_BLOB_CHARS:
        findings.append(_finding(1, f"<blob len={len(blob)} > cap {MAX_BLOB_CHARS}>", SurfaceKind.OBFUSCATION, "oversized-blob"))
    for line_no, line in enumerate(blob.splitlines(), start=1):
        if len(line) > MAX_LINE_CHARS:
            findings.append(_finding(line_no, f"<line len={len(line)} > cap {MAX_LINE_CHARS}>", SurfaceKind.OBFUSCATION, "oversized-line"))
    return findings


def _findings_for(blob: str, pattern: re.Pattern[str], kind: SurfaceKind, signal: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(blob.splitlines(), start=1):
        for match in pattern.finditer(line):
            findings.append(_finding(line_no, match.group(0).strip(), kind, signal))
    return findings


def _finding(line: int, detail: str, kind: SurfaceKind, signal: str) -> Finding:
    return Finding(
        kind=kind,
        file=MEMORY_REL,
        line=line,
        detail=detail,
        confidence=Confidence.LITERAL,
        extra={"signal": signal},
    )
