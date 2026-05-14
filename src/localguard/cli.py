from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit, cache as cache_mod, deps as deps_mod, diff, doctor as doctor_mod, egress as egress_mod, hook, init_hook as init_hook_mod, inspect as inspect_mod, library_refresh as library_refresh_mod, manifest, preflight as preflight_mod


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
    _add_preflight(sub)
    _add_accept(sub)
    _add_deps(sub)
    _add_tree(sub)
    _add_library(sub)
    _add_cache(sub)
    _add_egress(sub)
    _add_diff_versions(sub)
    _add_init_hook(sub)
    _add_doctor(sub)
    _add_hook_bash(sub)
    return parser


def _add_diff_versions(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("diff-versions", help="Compare two versions of the same package; report new/removed surfaces and score delta.")
    p.add_argument("name", help="Package name (e.g. requests or @modelcontextprotocol/server-filesystem).")
    p.add_argument("from_version", metavar="FROM", help="Baseline version.")
    p.add_argument("to_version", metavar="TO", help="Candidate version.")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_handle_diff_versions)


def _handle_diff_versions(args: argparse.Namespace) -> int:
    sep = "@" if (args.ecosystem == "npm" or args.name.startswith("@")) else "=="
    from_spec = f"{args.name}{sep}{args.from_version}"
    to_spec = f"{args.name}{sep}{args.to_version}"
    from_report, from_pkg, _ = inspect_mod.inspect(from_spec, ecosystem=args.ecosystem)
    to_report, to_pkg, _ = inspect_mod.inspect(to_spec, ecosystem=args.ecosystem)
    drift = diff.diff_reports(from_report.to_dict(), to_report.to_dict())
    payload = drift.to_dict()
    payload["name"] = from_pkg.name
    payload["ecosystem"] = from_pkg.ecosystem
    payload["from_version"] = from_pkg.version
    payload["to_version"] = to_pkg.version
    if args.json:
        _emit_json(payload, pretty=True)
        return 0 if not drift.has_drift else 1
    sys.stdout.write(f"{from_pkg.name} ({from_pkg.ecosystem}): {from_pkg.version} -> {to_pkg.version}\n")
    delta = payload["score_delta"]
    delta_str = f"{delta:+d}" if delta is not None else "?"
    sys.stdout.write(f"score: {payload['score_before']} -> {payload['score_after']} ({delta_str})\n")
    if drift.new_findings:
        sys.stdout.write("\nNEW surfaces:\n")
        for kind, items in drift.new_findings.items():
            sys.stdout.write(f"  + {kind} ({len(items)})\n")
            for f in items[:5]:
                sys.stdout.write(f"      {_describe_finding(f)}\n")
            if len(items) > 5:
                sys.stdout.write(f"      ... +{len(items)-5} more\n")
    if drift.removed_findings:
        sys.stdout.write("\nREMOVED surfaces:\n")
        for kind, items in drift.removed_findings.items():
            sys.stdout.write(f"  - {kind} ({len(items)})\n")
    if not drift.new_findings and not drift.removed_findings:
        sys.stdout.write("\nno surface changes\n")
    return 0 if not drift.has_drift else 1


def _describe_finding(f: dict) -> str:
    extra = f.get("extra") or {}
    hint = extra.get("host") or extra.get("fqn") or extra.get("name") or extra.get("env_name") or extra.get("method") or ""
    loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
    return f"{hint}  [{loc}]" if hint else loc


def _add_egress(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("egress", help="Print an egress profile for a baselined package (for runtime-gate consumers).")
    p.add_argument("spec", help="name or name==version")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    p.set_defaults(handler=_handle_egress)


def _handle_egress(args: argparse.Namespace) -> int:
    name, _, version = args.spec.partition("==")
    report = manifest.find_library_entry(name, args.ecosystem, version=version or None)
    if not report:
        sys.stderr.write(f"no library entry for {args.spec} ({args.ecosystem}); run `localguard accept` first.\n")
        return 1
    profile = egress_mod.profile_from_report(report)
    _emit_json(profile, pretty=True)
    return 0


def _add_cache(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("cache", help="Inspect or prune LocalGuard's fetched-package cache.")
    cache_sub = p.add_subparsers(dest="cache_command", required=True)
    p_prune = cache_sub.add_parser("prune", help="Remove cached source trees that haven't been audited recently.")
    p_prune.add_argument("--older-than", type=int, default=cache_mod.DEFAULT_PRUNE_DAYS, metavar="DAYS")
    p_prune.add_argument("--dry-run", action="store_true")
    p_prune.set_defaults(handler=_handle_cache_prune)


def _handle_cache_prune(args: argparse.Namespace) -> int:
    result = cache_mod.prune(older_than_days=args.older_than, dry_run=args.dry_run)
    label = "would remove" if args.dry_run else "removed"
    if not result.candidates:
        sys.stdout.write(f"nothing older than {args.older_than} days\n")
        return 0
    for entry in result.candidates:
        sys.stdout.write(f"  {label}: {entry.ecosystem}/{entry.name}=={entry.version}  ({entry.size_bytes/1024:.1f} KiB, {entry.age_days:.1f}d old)\n")
    sys.stdout.write(f"\n{len(result.candidates)} entries, {result.bytes_freed/1024/1024:.1f} MiB {'would be freed' if args.dry_run else 'freed'}\n")
    return 0


def _add_init_hook(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("init-hook", help="Register the LocalGuard PreToolUse hook into Claude Code's settings.json.")
    p.add_argument("--settings", type=Path, default=None, help="Override path to settings.json (default: ~/.claude/settings.json).")
    p.add_argument("--binary", type=Path, default=None, help="Override path to the localguard executable.")
    p.add_argument("--force", action="store_true", help="Replace an existing localguard hook command instead of leaving it alone.")
    p.set_defaults(handler=_handle_init_hook)


def _handle_init_hook(args: argparse.Namespace) -> int:
    try:
        result = init_hook_mod.install_hook(settings=args.settings, binary=args.binary, force=args.force)
    except FileNotFoundError as exc:
        sys.stderr.write(f"init-hook: {exc}\n")
        return 1
    sys.stdout.write(f"settings: {result.settings_path}\n")
    sys.stdout.write(f"command:  {result.hook_command}\n")
    sys.stdout.write(f"status:   {result.status}\n")
    if result.status == "already-present":
        sys.stdout.write("note: a localguard hook is already wired; re-run with --force to overwrite its command.\n")
    elif result.status in {"added", "replaced"}:
        sys.stdout.write("note: restart Claude Desktop (hrcc) for the new hook to load.\n")
    return 0


def _add_library(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("library", help="Inspect or prune the baselined-package library.")
    lib_sub = p.add_subparsers(dest="library_command", required=True)

    p_list = lib_sub.add_parser("list", help="List every baselined package (newest first).")
    p_list.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(handler=_handle_library_list)

    p_show = lib_sub.add_parser("show", help="Show a baselined package's full report.")
    p_show.add_argument("spec", help="name or name==version")
    p_show.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    p_show.set_defaults(handler=_handle_library_show)

    p_forget = lib_sub.add_parser("forget", help="Remove a baselined entry (so the next install must re-accept).")
    p_forget.add_argument("spec", help="name==version")
    p_forget.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    p_forget.add_argument("--yes", action="store_true")
    p_forget.set_defaults(handler=_handle_library_forget)

    p_stats = lib_sub.add_parser("stats", help="Health glance: per-ecosystem counts, score distribution, oldest/newest entry.")
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(handler=_handle_library_stats)

    p_refresh = lib_sub.add_parser("refresh", help="Re-audit every baselined package at its stored version and rewrite the report (use after detector or rubric changes).")
    p_refresh.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p_refresh.add_argument("--name", default=None, help="Substring filter on package name.")
    p_refresh.add_argument("--dry-run", action="store_true")
    p_refresh.set_defaults(handler=_handle_library_refresh)


def _handle_library_list(args: argparse.Namespace) -> int:
    rows = manifest.iter_library(ecosystem=args.ecosystem)
    rows.sort(key=lambda r: (r.get("audited_at") or ""), reverse=True)
    if args.json:
        _emit_json(rows, pretty=True)
        return 0
    if not rows:
        sys.stdout.write("(library is empty)\n")
        return 0
    sys.stdout.write(f"{'PACKAGE':<40} {'VERSION':<16} {'ECO':<6} {'SCORE':<6} AUDITED\n")
    for r in rows:
        sys.stdout.write(f"{r['name']:<40} {str(r.get('version') or '?'):<16} {r['ecosystem']:<6} {str(r.get('score') or '?'):<6} {r.get('audited_at') or '?'}\n")
    sys.stdout.write(f"\n{len(rows)} entries\n")
    return 0


def _handle_library_stats(args: argparse.Namespace) -> int:
    stats = manifest.library_stats()
    if args.json:
        _emit_json(stats, pretty=True)
        return 0
    if not stats["total"]:
        sys.stdout.write("(library is empty)\n")
        return 0
    sys.stdout.write(f"total entries: {stats['total']}\n")
    sys.stdout.write(f"size on disk:  {stats['size_bytes']/1024:.1f} KiB\n")
    sys.stdout.write("\nby ecosystem:\n")
    for eco, n in stats["by_ecosystem"].items():
        sys.stdout.write(f"  {eco:<6} {n}\n")
    sys.stdout.write("\nscore distribution:\n")
    sys.stdout.write(f"  >= 90 (auto-baselined):     {stats['score_bands']['high']}\n")
    sys.stdout.write(f"  50-89 (manually accepted):  {stats['score_bands']['mid']}\n")
    sys.stdout.write(f"  <  50 (override required):  {stats['score_bands']['low']}\n")
    sys.stdout.write(f"  unscored:                   {stats['score_bands']['unscored']}\n")
    if stats["mean_score"] is not None:
        sys.stdout.write(f"  mean: {stats['mean_score']:.1f}   median: {stats['median_score']}\n")
    if stats["oldest"]:
        sys.stdout.write(f"\noldest: {stats['oldest']['name']}=={stats['oldest']['version']} ({stats['oldest']['audited_at']})\n")
        sys.stdout.write(f"newest: {stats['newest']['name']}=={stats['newest']['version']} ({stats['newest']['audited_at']})\n")
    return 0


def _handle_library_show(args: argparse.Namespace) -> int:
    name, _, version = args.spec.partition("==")
    report = manifest.find_library_entry(name, args.ecosystem, version=version or None)
    if not report:
        sys.stderr.write(f"no library entry for {args.spec} ({args.ecosystem})\n")
        return 1
    _emit_json(report, pretty=True)
    return 0


def _handle_library_refresh(args: argparse.Namespace) -> int:
    def report_outcome(o):
        if o.status == "refreshed":
            delta = "" if o.old_score is None or o.new_score is None or o.new_score == o.old_score else f"  (score {o.old_score} -> {o.new_score})"
            verb = "would refresh" if args.dry_run else "refreshed"
            sys.stdout.write(f"  {verb}: {o.ecosystem}/{o.name}=={o.version}{delta}\n")
        elif o.status == "error":
            sys.stdout.write(f"  SKIPPED: {o.ecosystem}/{o.name}=={o.version} ({o.error})\n")
    summary = library_refresh_mod.refresh(ecosystem=args.ecosystem, name_pattern=args.name, dry_run=args.dry_run, on_progress=report_outcome)
    sys.stdout.write(f"\n{summary.refreshed} refreshed, {summary.errors} errors")
    if args.dry_run:
        sys.stdout.write("  (dry-run)")
    sys.stdout.write("\n")
    return 0 if summary.errors == 0 else 1


def _handle_library_forget(args: argparse.Namespace) -> int:
    name, _, version = args.spec.partition("==")
    if not version:
        sys.stderr.write("forget requires name==version\n")
        return 2
    if not args.yes:
        sys.stdout.write(f"Remove library baseline for {name}=={version} ({args.ecosystem})? Type 'forget' to confirm: ")
        sys.stdout.flush()
        if sys.stdin.readline().strip().lower() != "forget":
            sys.stdout.write("aborted\n")
            return 1
    removed = manifest.remove_library_entry(name, args.ecosystem, version)
    if not removed:
        sys.stderr.write(f"no entry found for {name}=={version} ({args.ecosystem})\n")
        return 1
    sys.stdout.write(f"removed {name}=={version} ({args.ecosystem})\n")
    return 0


def _add_deps(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("deps", help="Fetch a package and list its declared immediate dependencies.")
    p.add_argument("spec")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.set_defaults(handler=_handle_deps)


def _add_tree(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("tree", help="Recursively audit a package and its declared dependencies; print the tree with verdicts.")
    p.add_argument("spec")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.add_argument("--max-depth", type=int, default=deps_mod.DEFAULT_MAX_DEPTH)
    p.set_defaults(handler=_handle_tree)


def _handle_tree(args: argparse.Namespace) -> int:
    node = deps_mod.audit_tree(args.spec, ecosystem=args.ecosystem, max_depth=args.max_depth)
    sys.stdout.write(deps_mod.render_tree(node) + "\n")
    return 1 if node.blocked else 0


def _handle_deps(args: argparse.Namespace) -> int:
    from . import fetch
    spec = fetch.parse_spec(args.spec, ecosystem_override=args.ecosystem)
    unpacked = fetch.fetch_package(spec)
    audit_root = inspect_mod._pick_audit_root(unpacked, spec.ecosystem)
    declared = deps_mod.extract_deps(audit_root, spec.ecosystem)
    sys.stdout.write(f"{spec.name}=={spec.version or '(unversioned)'} ({spec.ecosystem})\n")
    if not declared:
        sys.stdout.write("  (no declared dependencies)\n")
        return 0
    for dep in declared:
        spec_str = f" {dep.specifier}" if dep.specifier else ""
        sys.stdout.write(f"  - {dep.name}{spec_str}\n")
    return 0


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


def _add_preflight(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("preflight", help="Audit + library diff a package spec; exit non-zero if unsafe.")
    p.add_argument("spec")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.add_argument("--min-score", type=int, default=preflight_mod.DEFAULT_MIN_SCORE)
    p.add_argument("--accept-new", action="store_true", help="Auto-pin a first-time-seen package if it meets the score threshold.")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_handle_preflight)


def _add_accept(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("accept", help="Fetch + audit a package, then pin it into the library as a deliberate baseline.")
    p.add_argument("spec")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default=None)
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    p.add_argument("--with-deps", action="store_true", help="Recursively audit the dep closure and baseline every acceptable node.")
    p.add_argument("--max-depth", type=int, default=deps_mod.DEFAULT_MAX_DEPTH)
    p.set_defaults(handler=_handle_accept)


def _handle_accept(args: argparse.Namespace) -> int:
    if args.with_deps:
        return _handle_accept_with_deps(args)
    report, spec, _ = inspect_mod.inspect(args.spec, ecosystem=args.ecosystem)
    report_dict = report.to_dict()
    score = (report_dict.get("score") or {}).get("final_score")
    sys.stdout.write(f"package: {spec.name}=={spec.version or '(unversioned)'} ({spec.ecosystem})\n")
    sys.stdout.write(f"score:   {score}/100\n")
    sys.stdout.write(_finding_summary(report_dict) + "\n")
    if not args.yes:
        sys.stdout.write("Type 'accept' to baseline this package, anything else to abort: ")
        sys.stdout.flush()
        reply = sys.stdin.readline().strip().lower()
        if reply != "accept":
            sys.stdout.write("aborted; no library entry written\n")
            return 1
    library_path = manifest.write_library_entry(report_dict)
    sys.stdout.write(f"baselined: {library_path}\n")
    return 0


def _handle_accept_with_deps(args: argparse.Namespace) -> int:
    node = deps_mod.audit_tree(args.spec, ecosystem=args.ecosystem, max_depth=args.max_depth)
    sys.stdout.write(deps_mod.render_tree(node) + "\n")
    pending, hard_blockers = _classify_tree_for_accept(node)
    if hard_blockers:
        sys.stdout.write("\nrefusing: the following nodes are not acceptable via this flow (low-score / drift / error):\n")
        for n, reason in hard_blockers:
            sys.stdout.write(f"  - {n.name}=={n.version or '?'} ({n.ecosystem}): {reason}\n")
        sys.stdout.write("review them manually before retrying.\n")
        return 1
    if not pending:
        sys.stdout.write("\nnothing to accept: every node is already safe or baselined.\n")
        return 0
    sys.stdout.write(f"\n{len(pending)} package(s) will be baselined:\n")
    for n in pending:
        sys.stdout.write(f"  + {n.name}=={n.version} ({n.ecosystem})\n")
    if not args.yes:
        sys.stdout.write("Type 'accept' to baseline all listed packages, anything else to abort: ")
        sys.stdout.flush()
        if sys.stdin.readline().strip().lower() != "accept":
            sys.stdout.write("aborted; no library entries written\n")
            return 1
    written: list[str] = []
    for n in pending:
        sep = "@" if n.ecosystem == "npm" else "=="
        report_dict, _spec_back, _root = inspect_mod.inspect(f"{n.name}{sep}{n.version}", ecosystem=n.ecosystem)
        path = manifest.write_library_entry(report_dict.to_dict())
        written.append(str(path))
    sys.stdout.write(f"baselined {len(written)} entries:\n")
    for p in written:
        sys.stdout.write(f"  {p}\n")
    return 0


def _classify_tree_for_accept(node):
    pending: list = []
    hard: list = []
    seen: set = set()
    for n in _walk(node):
        if n.cycle or n.truncated:
            continue
        key = (n.ecosystem, n.name.lower(), n.version or "")
        if key in seen:
            continue
        seen.add(key)
        if n.error:
            hard.append((n, f"error: {n.error}"))
            continue
        own = n.verdict.status if n.verdict else None
        if own == "first-encounter-needs-accept":
            pending.append(n)
        elif own in {"low-score", "drift"}:
            hard.append((n, own))
    return pending, hard


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _finding_summary(report_dict: dict) -> str:
    counts: dict[str, int] = {}
    for f in report_dict.get("findings") or []:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1
    if not counts:
        return "findings: none"
    parts = [f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    return "findings: " + ", ".join(parts)


def _add_doctor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="Self-test: verify binary on PATH, hook wired, library + cache consistent.")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=_handle_doctor)


def _handle_doctor(args: argparse.Namespace) -> int:
    report = doctor_mod.run()
    if args.json:
        _emit_json({
            "ok": report.ok,
            "warn": report.warn,
            "fail": report.fail,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in report.checks],
        }, pretty=True)
        return 0 if report.healthy else 1
    width = max(len(c.name) for c in report.checks)
    label = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}
    for c in report.checks:
        sys.stdout.write(f"{c.name:<{width}}  {label[c.status]:<5}  {c.detail}\n")
    sys.stdout.write(f"\ndoctor: {report.ok} ok, {report.warn} warn, {report.fail} fail\n")
    return 0 if report.healthy else 1


def _add_hook_bash(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("hook-bash", help="Claude Code PreToolUse hook: reads tool_use JSON from stdin, blocks unsafe installs.")
    p.set_defaults(handler=_handle_hook_bash)


def _handle_hook_bash(args: argparse.Namespace) -> int:
    return hook.main_entry()


def _handle_preflight(args: argparse.Namespace) -> int:
    verdict = preflight_mod.preflight(
        args.spec,
        ecosystem=args.ecosystem,
        min_score=args.min_score,
        accept_new=args.accept_new,
    )
    if args.json:
        _emit_json(verdict.to_dict(), pretty=True)
    else:
        sys.stdout.write(verdict.human_summary() + "\n")
    return 0 if verdict.safe else 1


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
