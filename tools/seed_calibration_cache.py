"""Download the calibration-suite tarballs and record their SHA256 hashes.

Reads tests/calibration/pinned_scores.json, fetches each pypi/npm spec
from its registry, stores the tarball under tests/calibration/data/,
and writes tests/calibration/data_index.json with the hash + relative
path. Subsequent runs are idempotent: existing tarballs with matching
hashes are skipped.

Usage:
    python tools/seed_calibration_cache.py             # all rows
    python tools/seed_calibration_cache.py --eco pypi  # just pypi
    python tools/seed_calibration_cache.py --eco npm   # just npm
    python tools/seed_calibration_cache.py --spec requests==2.31.0
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PINNED_PATH = ROOT / "tests" / "calibration" / "pinned_scores.json"
DATA_DIR = ROOT / "tests" / "calibration" / "data"
INDEX_PATH = ROOT / "tests" / "calibration" / "data_index.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "localguard-calibration-seed/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "localguard-calibration-seed/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)


def _resolve_pypi_sdist(name: str, version: str) -> tuple[str, str]:
    """Return (filename, url) of the sdist for name==version. Prefer
    .tar.gz; fall back to first available source distribution."""
    data = _http_get_json(f"https://pypi.org/pypi/{name}/{version}/json")
    urls = data.get("urls") or []
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    if not sdists:
        raise RuntimeError(f"{name}=={version}: no sdist on PyPI (only wheels)")
    # Prefer .tar.gz over .zip for unified handling.
    sdists.sort(key=lambda u: 0 if u["filename"].endswith(".tar.gz") else 1)
    chosen = sdists[0]
    return chosen["filename"], chosen["url"]


def _resolve_npm_tarball(name: str, version: str) -> tuple[str, str]:
    """Return (filename, url) of the .tgz for name@version."""
    # url-encode the name; @scope/pkg becomes @scope%2Fpkg.
    encoded = name.replace("/", "%2F") if name.startswith("@") else name
    data = _http_get_json(f"https://registry.npmjs.org/{encoded}/{version}")
    dist = data.get("dist") or {}
    tarball_url = dist.get("tarball")
    if not tarball_url:
        raise RuntimeError(f"{name}@{version}: no dist.tarball")
    filename = Path(tarball_url).name
    return filename, tarball_url


def _split_pypi(spec: str) -> tuple[str, str]:
    name, _, version = spec.partition("==")
    return name, version


def _split_npm(spec: str) -> tuple[str, str]:
    if spec.startswith("@"):
        scope_path, _, version = spec.rpartition("@")
        return scope_path, version
    name, _, version = spec.partition("@")
    return name, version


def _load_index() -> dict[str, dict[str, Any]]:
    if INDEX_PATH.exists():
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return {}


def _save_index(index: dict[str, dict[str, Any]]) -> None:
    INDEX_PATH.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")


def _seed_one(eco: str, spec: str, index: dict[str, dict[str, Any]]) -> str:
    if eco == "pypi":
        name, version = _split_pypi(spec)
        filename, url = _resolve_pypi_sdist(name, version)
    elif eco == "npm":
        name, version = _split_npm(spec)
        filename, url = _resolve_npm_tarball(name, version)
    else:
        raise ValueError(f"unknown ecosystem: {eco}")

    rel_path = f"{eco}/{filename}"
    dest = DATA_DIR / rel_path
    existing = index.get(eco, {}).get(spec)
    if dest.exists() and existing and _sha256(dest) == existing.get("sha256"):
        return "cached"

    _download(url, dest)
    sha = _sha256(dest)
    index.setdefault(eco, {})[spec] = {"path": rel_path, "sha256": sha, "url": url}
    return "downloaded"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eco", choices=["pypi", "npm"], default=None)
    parser.add_argument("--spec", default=None, help="Single spec to (re)fetch")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args(argv)

    pinned = json.loads(PINNED_PATH.read_text(encoding="utf-8"))
    index = _load_index()

    targets: list[tuple[str, str]] = []
    for eco in ("pypi", "npm"):
        if args.eco and args.eco != eco:
            continue
        for row in pinned.get(eco, []):
            if args.spec and row["spec"] != args.spec:
                continue
            targets.append((eco, row["spec"]))

    if not targets:
        print("no targets matched", file=sys.stderr)
        return 1

    failures: list[tuple[str, str, str]] = []
    for i, (eco, spec) in enumerate(targets, 1):
        try:
            status = _seed_one(eco, spec, index)
            print(f"[{i}/{len(targets)}] {eco} {spec}: {status}")
            _save_index(index)
        except Exception as e:
            print(f"[{i}/{len(targets)}] {eco} {spec}: FAILED -- {e}", file=sys.stderr)
            failures.append((eco, spec, str(e)))
            if not args.continue_on_error:
                return 2

    if failures:
        print(f"\n{len(failures)} failure(s):", file=sys.stderr)
        for eco, spec, msg in failures:
            print(f"  {eco} {spec}: {msg}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
