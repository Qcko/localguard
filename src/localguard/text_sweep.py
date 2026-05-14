from __future__ import annotations

import math
import re

from .report import Finding, SurfaceKind
from .walker import SourceFile


URL_PATTERN = re.compile(r"\bhttps?://([A-Za-z0-9.\-_]+)(?::\d+)?(/[^\s\"'`<>]*)?")
IPV4_PATTERN = re.compile(r"\b(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
BASE64_PATTERN = re.compile(r"['\"`]([A-Za-z0-9+/=]{120,})['\"`]")

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
# RFC 2606 reserved hostnames for documentation/testing. Findings against
# these are noise in docstrings, README examples, and >>> doctest lines.
DOC_HOSTS = {"example.com", "example.org", "example.net", "example.edu"}
DOC_TLDS = (".example", ".test", ".invalid", ".localhost")
TELEMETRY_HOSTS = {
    "sentry.io", "ingest.sentry.io",
    "api.mixpanel.com", "mixpanel.com",
    "api.segment.io", "segment.io",
    "app.posthog.com", "posthog.com",
    "www.google-analytics.com", "google-analytics.com",
    "www.googletagmanager.com",
    "api.amplitude.com", "amplitude.com",
    "browser-intake-datadoghq.com", "datadoghq.com",
    "static.hotjar.com", "hotjar.com",
    "fullstory.com",
}

ENV_REFERENCE_PATTERN = re.compile(r"(?:process\.env\.|os\.environ\[|os\.getenv\()['\"]?([A-Za-z0-9_]+)['\"]?")
SECRET_NAME_PATTERN = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)


def sweep_text(source: SourceFile) -> list[Finding]:
    non_code = _non_code_lines(source.text, source.language)
    findings: list[Finding] = []
    findings.extend(_find_urls(source, non_code))
    findings.extend(_find_bare_ipv4(source, non_code))
    findings.extend(_find_env_secrets(source))
    findings.extend(_find_obfuscation_blobs(source))
    return findings


def _non_code_lines(text: str, language: str) -> set[int]:
    """1-based line numbers that are comments or docstrings.

    URL / IP findings on these lines are noise (README examples, docstring
    doctests, RFC references). Conservative: a line is "non-code" only when
    its content is obviously inside a comment or triple-quoted block; we
    do not attempt to detect strings in expression context.
    """
    lines = text.splitlines()
    non_code: set[int] = set()
    if language == "python":
        in_triple: str | None = None
        for idx, line in enumerate(lines, start=1):
            if in_triple is not None:
                non_code.add(idx)
                if in_triple in line:
                    in_triple = None
                continue
            stripped = line.lstrip()
            if stripped.startswith("#"):
                non_code.add(idx)
                continue
            for marker in ('"""', "'''"):
                count = line.count(marker)
                if count == 0:
                    continue
                non_code.add(idx)
                if count % 2 == 1:
                    in_triple = marker
                break
    elif language == "javascript":
        in_block = False
        for idx, line in enumerate(lines, start=1):
            if in_block:
                non_code.add(idx)
                if "*/" in line:
                    in_block = False
                continue
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("*"):
                non_code.add(idx)
                continue
            if "/*" in line:
                non_code.add(idx)
                # Block may close on same line; otherwise carry the flag.
                close_pos = line.find("*/", line.index("/*") + 2)
                if close_pos < 0:
                    in_block = True
    return non_code


def dedupe_hosts(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    deduped: list[Finding] = []
    for finding in findings:
        if finding.kind != SurfaceKind.HARDCODED_HOST:
            deduped.append(finding)
            continue
        host = finding.extra.get("host", "")
        if host in seen:
            continue
        seen.add(host)
        deduped.append(finding)
    return deduped


def _find_urls(source: SourceFile, non_code: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        if line_no in non_code:
            continue
        for match in URL_PATTERN.finditer(line):
            host = match.group(1).lower()
            if host in LOCAL_HOSTS:
                continue
            if host in DOC_HOSTS or host.endswith(DOC_TLDS):
                continue
            kind = SurfaceKind.TELEMETRY_ENDPOINT if host in TELEMETRY_HOSTS else SurfaceKind.HARDCODED_HOST
            findings.append(Finding(
                kind=kind,
                file=source.rel,
                line=line_no,
                detail=match.group(0),
                extra={"host": host},
            ))
    return findings


def _find_bare_ipv4(source: SourceFile, non_code: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        if line_no in non_code:
            continue
        for match in IPV4_PATTERN.finditer(line):
            ip = match.group(1)
            if _is_non_routable_ipv4(ip):
                continue
            findings.append(Finding(
                kind=SurfaceKind.HARDCODED_HOST,
                file=source.rel,
                line=line_no,
                detail=ip,
                extra={"host": ip},
            ))
    return findings


def _is_non_routable_ipv4(ip: str) -> bool:
    """IPv4 addresses that are guaranteed not to reach a real internet host.

    Private (RFC 1918): 10.x, 172.16-31.x, 192.168.x. Loopback: 127.x.
    Reserved: 0.x. Link-local: 169.254.x.
    Documentation (RFC 5737): 192.0.2.x, 198.51.100.x, 203.0.113.x.
    Multicast and reserved: anything 224.x and above.
    """
    if ip.startswith(("127.", "0.", "10.", "169.254.")):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return True
    parts = ip.split(".")
    first = int(parts[0])
    if first == 172 and 16 <= int(parts[1]) <= 31:
        return True
    if first >= 224:
        return True
    return False


def _find_env_secrets(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for match in ENV_REFERENCE_PATTERN.finditer(line):
            name = match.group(1)
            if SECRET_NAME_PATTERN.search(name):
                findings.append(Finding(
                    kind=SurfaceKind.ENV_SECRET_READ,
                    file=source.rel,
                    line=line_no,
                    detail=match.group(0),
                    extra={"env_name": name},
                ))
    return findings


def _find_obfuscation_blobs(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for match in BASE64_PATTERN.finditer(line):
            blob = match.group(1)
            if _entropy(blob) < 4.0:
                continue
            findings.append(Finding(
                kind=SurfaceKind.OBFUSCATION,
                file=source.rel,
                line=line_no,
                detail=f"<base64-like blob len={len(blob)}>",
                extra={"length": len(blob), "entropy": round(_entropy(blob), 2)},
            ))
    return findings


def _entropy(blob: str) -> float:
    if not blob:
        return 0.0
    counts: dict[str, int] = {}
    for char in blob:
        counts[char] = counts.get(char, 0) + 1
    total = len(blob)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
