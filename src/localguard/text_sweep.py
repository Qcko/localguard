from __future__ import annotations

import math
import re

from .report import Finding, SurfaceKind
from .walker import SourceFile


URL_PATTERN = re.compile(r"\bhttps?://([A-Za-z0-9.\-_]+)(?::\d+)?(/[^\s\"'`<>]*)?")
IPV4_PATTERN = re.compile(r"\b(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
BASE64_PATTERN = re.compile(r"['\"`]([A-Za-z0-9+/=]{120,})['\"`]")

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
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
    findings: list[Finding] = []
    findings.extend(_find_urls(source))
    findings.extend(_find_bare_ipv4(source))
    findings.extend(_find_env_secrets(source))
    findings.extend(_find_obfuscation_blobs(source))
    return findings


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


def _find_urls(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for match in URL_PATTERN.finditer(line):
            host = match.group(1).lower()
            if host in LOCAL_HOSTS:
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


def _find_bare_ipv4(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for match in IPV4_PATTERN.finditer(line):
            ip = match.group(1)
            if ip.startswith(("127.", "0.", "10.", "192.168.", "169.254.")):
                continue
            findings.append(Finding(
                kind=SurfaceKind.HARDCODED_HOST,
                file=source.rel,
                line=line_no,
                detail=ip,
                extra={"host": ip},
            ))
    return findings


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
