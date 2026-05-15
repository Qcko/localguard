"""Dump observed (score, role_typical_share, profile, classify) for every
cached calibration tarball. Run after the seed tool to populate / update
pinned_scores.json.

Output is tab-separated: spec  observed_score  observed_share  profile  classify
"""
from __future__ import annotations

import json
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from localguard import audit, preflight, rubric  # noqa: E402
from localguard.walker import PACKAGE_AUDIT_SKIP_DIRS  # noqa: E402

CALIB_DIR = ROOT / "tests" / "calibration"
INDEX_PATH = CALIB_DIR / "data_index.json"
PINNED_PATH = CALIB_DIR / "pinned_scores.json"


def _unpack(tarball: Path, work_dir: Path, *, ecosystem: str) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as tar:
        tar.extractall(work_dir)
    if ecosystem == "npm":
        pkg = work_dir / "package"
        if pkg.is_dir():
            return pkg
    entries = [p for p in work_dir.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return work_dir


def main() -> int:
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8")) if INDEX_PATH.exists() else {}
    pinned = json.loads(PINNED_PATH.read_text(encoding="utf-8"))

    print(f"{'spec':<40} {'score':>5} {'share':>6} {'profile':<22} {'classify':<22} {'pinned_score':>12} {'pinned_share':>12}")
    print("-" * 130)

    for eco in ("pypi", "npm"):
        rows_by_spec = {r["spec"]: r for r in pinned.get(eco, [])}
        for spec, meta in index.get(eco, {}).items():
            tarball = CALIB_DIR / "data" / meta["path"]
            if not tarball.exists():
                continue
            name = spec.split("==")[0] if eco == "pypi" else (spec.rsplit("@", 1)[0] if spec.startswith("@") else spec.split("@", 1)[0])
            detected = rubric.detect_profile_from_name(name, eco)
            profile, reason = detected if detected else (None, None)
            with tempfile.TemporaryDirectory() as tmp:
                root = _unpack(tarball, Path(tmp), ecosystem=eco)
                report = audit.audit_path(root, profile=profile, profile_reason=reason, skip_dirs=PACKAGE_AUDIT_SKIP_DIRS)
            classify = preflight._classify_blocked_status(report.to_dict()) if report.score.final_score < 50 else "n/a"
            pinned_row = rows_by_spec.get(spec, {})
            pinned_score = pinned_row.get("score", "?")
            pinned_share = pinned_row.get("role_typical_share", "-")
            print(f"{spec:<40} {report.score.final_score:>5} {report.score.role_typical_share:>6.2f} {(report.profile or '-'):<22} {classify:<22} {str(pinned_score):>12} {str(pinned_share):>12}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
