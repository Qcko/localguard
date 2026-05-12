from __future__ import annotations

from typing import Any


def profile_from_report(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings") or []
    static_hosts = _dedupe_strs([
        host
        for f in findings
        if f.get("kind") == "outbound_network"
        and (host := (f.get("extra") or {}).get("host"))
    ])
    dynamic_callsites = [
        {
            "file": f.get("file"),
            "line": f.get("line"),
            "fqn": (f.get("extra") or {}).get("fqn"),
        }
        for f in findings
        if f.get("kind") == "outbound_dynamic"
    ]
    subprocess_callsites = [
        {
            "file": f.get("file"),
            "line": f.get("line"),
            "fqn": (f.get("extra") or {}).get("fqn") or (f.get("extra") or {}).get("method"),
            "detail": f.get("detail"),
        }
        for f in findings
        if f.get("kind") == "subprocess"
    ]
    listening_ports = [
        {
            "file": f.get("file"),
            "line": f.get("line"),
            "fqn": (f.get("extra") or {}).get("fqn"),
        }
        for f in findings
        if f.get("kind") == "listening_port"
    ]
    return {
        "package": {
            "name": report.get("name"),
            "version": report.get("version"),
            "ecosystem": report.get("ecosystem"),
        },
        "egress": {
            "static_hosts": sorted(static_hosts),
            "dynamic_callsites": dynamic_callsites,
            "subprocess_callsites": subprocess_callsites,
            "listening_ports": listening_ports,
        },
        "policy_hints": {
            "fully_offline_capable": not (dynamic_callsites or static_hosts or listening_ports),
            "allowlist_sufficient": bool(static_hosts) and not dynamic_callsites,
            "needs_proxy_or_block": bool(dynamic_callsites),
        },
    }


def _dedupe_strs(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
