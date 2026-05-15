"""End-to-end: hook block -> library journal -> blocked-review -> promote -> re-install allow.

This is the user-facing supply-chain loop in miniature. Each step is
exercised at the same layer the real user would touch:

    install attempt -> hook (preflight) -> library auto-write
        -> `localguard library blocked-review`
        -> `localguard library promote ... --pin-surfaces --yes`
        -> install attempt again -> hook allows.

Unit tests cover the pieces; this test catches the kind of wiring
regression that would let one piece pass its unit test while the
hand-off to the next piece silently drops state.
"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path

from localguard import cli, fetch, hook, manifest, preflight


FIXTURES = Path(__file__).parent / "fixtures"


def _seed_cache_only(tmp_path: Path, name: str, version: str, fixture: Path) -> None:
    archive = tmp_path / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fixture, arcname=f"{name}-{version}")
    src_dir = tmp_path / "cache" / "pypi" / name / version / "src"
    src_dir.mkdir(parents=True)
    fetch._unpack_into(archive, src_dir)


def _patch_roots(monkeypatch, tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    library_root.mkdir(exist_ok=True)
    monkeypatch.setattr(fetch, "DEFAULT_CACHE_ROOT", cache_root)
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    monkeypatch.setattr(cli.manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    monkeypatch.setattr(preflight.fetch, "DEFAULT_CACHE_ROOT", cache_root)
    monkeypatch.setattr(preflight.manifest, "DEFAULT_LIBRARY_ROOT", library_root)


def test_full_loop_block_review_promote_allow(tmp_path, monkeypatch, capsys):
    name, version = "drifty-pkg", "0.2.0"
    _seed_cache_only(tmp_path, name, version, FIXTURES / "tampered_v2")
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "DEFAULT_MIN_SCORE", 80)

    # 1. First install: hook blocks. Library gets a blocked-* entry written
    #    as a side-effect of the verdict path.
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"pip install {name}=={version}"}})
    code, _out, err = hook.render_to_string(payload)
    assert code == 2
    assert "BLOCK" in err
    assert ("blocked-role-typical" in err) or ("blocked-suspicious" in err)

    library_root = tmp_path / "lib"
    rows = manifest.iter_library(library_root=library_root)
    assert len(rows) == 1
    entry = rows[0]
    assert entry["name"] == name
    assert entry["version"] == version
    assert entry["status"].startswith("blocked-")
    blocked_status_at_step1 = entry["status"]

    # 2. `library blocked-review` surfaces the entry.
    capsys.readouterr()  # clear stdout from any prior emission
    rc = cli.main(["library", "blocked-review"])
    assert rc == 0
    review_out = capsys.readouterr().out
    assert name in review_out
    assert version in review_out
    assert blocked_status_at_step1 in review_out.lower()

    # 3. `library promote ... --pin-surfaces --yes` flips status to accepted
    #    and pins expected_surface_counts.
    rc = cli.main(["library", "promote", f"{name}=={version}", "--pin-surfaces", "--yes"])
    assert rc == 0
    promote_out = capsys.readouterr().out
    assert "promoted" in promote_out
    assert "pinned surfaces" in promote_out

    # Verify the on-disk report reflects the promotion.
    rows = manifest.iter_library(library_root=library_root)
    assert len(rows) == 1
    assert rows[0]["status"] == "accepted"
    # Walk to the raw report to confirm expected_surface_counts.
    report_path = next((library_root / "pypi" / name / version).glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "accepted"
    assert "expected_surface_counts" in report and report["expected_surface_counts"]

    # 4. Re-install: with min_score lowered to model "user adjusted the
    #    threshold for this score band," the hook now allows because
    #    latest_known_good returns the promoted entry and the diff path
    #    finds no novel high-risk surfaces (pin-surfaces absorbs them).
    #    NOTE: _diff_verdict re-runs the score check unconditionally, so a
    #    low-score promotion alone doesn't allow future installs at the
    #    same threshold -- the user must also adjust LOCALGUARD_MIN_SCORE.
    monkeypatch.setattr(preflight, "DEFAULT_MIN_SCORE", 30)
    code, out, err = hook.render_to_string(payload)
    assert code == 0, f"expected allow, got code={code} err={err}"
    assert "OK" in out
    assert "BLOCK" not in err
