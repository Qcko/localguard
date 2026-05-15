"""Wipe and re-accept every accepted library entry against the current rubric.

Snapshots the existing library first (to /tmp/library_snapshot_<ts>.json),
moves the live library aside (rename, never delete), then iterates the
snapshot and calls `localguard accept <spec> --ecosystem ECO --yes` for
each previously-accepted entry. Blocked-* entries are skipped on purpose
-- they're a journal of declined installs, not trust baselines.

Failures are recorded; the script does NOT halt on the first error.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from localguard import cli, manifest  # noqa: E402


def main() -> int:
    library_root = manifest.DEFAULT_LIBRARY_ROOT
    if not library_root.exists():
        print(f"library {library_root} does not exist; nothing to do", file=sys.stderr)
        return 1

    rows = manifest.iter_library()
    ts = time.strftime("%Y%m%d-%H%M%S")
    snapshot_path = Path(os.environ.get("TEMP") or "/tmp") / f"localguard_library_snapshot_{ts}.json"
    snapshot_path.write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    print(f"snapshot: {snapshot_path} ({len(rows)} entries)")

    # Move the live library aside so a botched re-accept doesn't destroy state.
    backup = library_root.parent / f"library.backup-{ts}"
    print(f"moving {library_root} -> {backup}")
    shutil.move(str(library_root), str(backup))

    accepted = [r for r in rows if (r.get("status") or "accepted") == "accepted"]
    skipped = [r for r in rows if (r.get("status") or "accepted") != "accepted"]
    print(f"re-accepting {len(accepted)} entries; skipping {len(skipped)} non-accepted (blocked-*)")

    failures: list[tuple[str, str, str]] = []
    for i, row in enumerate(accepted, 1):
        name = row["name"]
        version = row.get("version")
        eco = row["ecosystem"]
        if not version:
            print(f"[{i}/{len(accepted)}] {eco} {name}: SKIP (no version)")
            continue
        sep = "@" if eco == "npm" else "=="
        spec = f"{name}{sep}{version}"
        print(f"[{i}/{len(accepted)}] {eco} {spec}", flush=True)
        try:
            rc = cli.main(["accept", spec, "--ecosystem", eco, "--yes"])
            if rc != 0:
                failures.append((eco, spec, f"exit code {rc}"))
        except SystemExit as e:
            failures.append((eco, spec, f"SystemExit({e.code})"))
        except Exception as e:
            failures.append((eco, spec, repr(e)))

    print(f"\ndone. failures: {len(failures)}")
    for eco, spec, msg in failures:
        print(f"  {eco} {spec}: {msg}")
    print(f"\nbackup of old library at: {backup}")
    print(f"snapshot of original metadata at: {snapshot_path}")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
