from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit, diff, inspect as inspect_mod, manifest


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="localguard", description="Supply-chain drift auditor for local-first projects.")
    sub = parser.add_subparsers(dest="command", required=True)
    _add_audit(sub)
    _add_pin(sub)
    _add_diff(sub)
    _add_inspect(sub)
    return parser


def _add_audit(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("audit", help="Audit a directory and print a JSON report.")
    p.add_argument("path", type=Path)
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(handler=_handle_audit)


def _add_pin(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("pin", help="Audit and pin the result as the known-good baseline.")
    p.add_argument("path", type=Path)
    p.add_argument("--project", type=Path, default=Path.cwd(), help="Project root (default: CWD).")
    p.add_argument("--skip-library", action="store_true")
    p.set_defaults(handler=_handle_pin)


def _add_diff(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("diff", help="Re-audit and diff against the pinned baseline.")
    p.add_argument("path", type=Path)
    p.add_argument("--project", type=Path, default=Path.cwd())
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(handler=_handle_diff)


def _add_inspect(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("inspect", help="Fetch a package from PyPI/npm and audit it.")
    p.add_argument("spec", help="Package spec, e.g. 'requests==2.31.0' or '@modelcontextprotocol/server-filesystem@0.6.0'")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(handler=_handle_inspect)


def _handle_inspect(args: argparse.Namespace) -> int:
    report, spec, root = inspect_mod.inspect(args.spec, ecosystem=args.ecosystem)
    payload = report.to_dict()
    payload["spec"] = {"name": spec.name, "version": spec.version, "ecosystem": spec.ecosystem}
    payload["audit_root"] = str(root)
    _emit_json(payload, pretty=args.pretty)
    return 0


def _handle_audit(args: argparse.Namespace) -> int:
    report = audit.audit_path(args.path)
    _emit_json(report.to_dict(), pretty=args.pretty)
    return 0


def _handle_pin(args: argparse.Namespace) -> int:
    report = audit.audit_path(args.path).to_dict()
    pin_path = manifest.write_pin(args.project, report)
    library_path = None if args.skip_library else manifest.write_library_entry(report)
    _emit_json({"pinned": str(pin_path), "library": str(library_path) if library_path else None, "name": report["name"], "score": report["score"]["final_score"]}, pretty=True)
    return 0


def _handle_diff(args: argparse.Namespace) -> int:
    candidate = audit.audit_path(args.path).to_dict()
    baseline = _resolve_baseline(args.project, candidate)
    if baseline is None:
        _emit_json({"error": "no baseline found — run `localguard pin` first"}, pretty=True)
        return 2
    drift = diff.diff_reports(baseline, candidate)
    _emit_json(drift.to_dict(), pretty=args.pretty)
    return 1 if drift.has_drift else 0


def _resolve_baseline(project_root: Path, candidate: dict) -> dict | None:
    pin = manifest.find_pinned_entry(project_root, candidate.get("name"), candidate["target_hash"])
    if pin and pin.get("target_hash") == candidate["target_hash"]:
        return manifest.library_lookup(pin["target_hash"], pin.get("name"), pin.get("ecosystem") or "unknown")
    return manifest.latest_known_good(candidate.get("name") or "", candidate.get("ecosystem") or "unknown")


def _emit_json(data, *, pretty: bool) -> None:
    indent = 2 if pretty else None
    sys.stdout.write(json.dumps(data, indent=indent, sort_keys=False))
    sys.stdout.write("\n")
