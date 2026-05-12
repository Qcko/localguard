from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CACHE_ROOT = Path(os.environ.get("LOCALGUARD_CACHE") or r"E:\localguard\cache")

NPM_SCOPED_PATTERN = re.compile(r"^@[^/]+/[^@]+(?:@.+)?$")
NPM_BARE_VERSIONED = re.compile(r"^[^@/]+@.+$")
PYPI_SPEC_PATTERN = re.compile(r"^([A-Za-z0-9_.\-]+)(?:==(.+))?$")


@dataclass(frozen=True)
class PackageSpec:
    name: str
    version: str | None
    ecosystem: str


class FetchError(RuntimeError):
    pass


def fetch_package(spec: PackageSpec, cache_root: Path = DEFAULT_CACHE_ROOT) -> Path:
    dest = _cache_dir(spec, cache_root)
    if _has_unpacked_contents(dest):
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    if spec.ecosystem == "pypi":
        _fetch_pypi(spec, dest)
    elif spec.ecosystem == "npm":
        _fetch_npm(spec, dest)
    else:
        raise FetchError(f"unknown ecosystem: {spec.ecosystem}")
    return dest


def resolve_latest_version(name: str, ecosystem: str) -> str | None:
    if ecosystem == "pypi":
        data = _http_get_json(f"https://pypi.org/pypi/{name}/json")
        return (data.get("info") or {}).get("version")
    if ecosystem == "npm":
        data = _http_get_json(f"https://registry.npmjs.org/{name}")
        return (data.get("dist-tags") or {}).get("latest")
    return None


def resolve_matching_version(name: str, ecosystem: str, specifier: str | None) -> str | None:
    if not specifier or specifier.strip() in {"", "*", "latest"}:
        return resolve_latest_version(name, ecosystem)
    if ecosystem == "pypi":
        return _resolve_pypi_match(name, specifier)
    if ecosystem == "npm":
        return _resolve_npm_match(name, specifier)
    return resolve_latest_version(name, ecosystem)


def _resolve_npm_match(name: str, specifier: str) -> str | None:
    import nodesemver
    if _looks_like_non_registry_spec(specifier):
        return resolve_latest_version(name, "npm")
    data = _http_get_json(f"https://registry.npmjs.org/{name}")
    versions = list((data.get("versions") or {}).keys())
    if not versions:
        return None
    try:
        match = nodesemver.max_satisfying(versions, specifier, loose=True)
    except (ValueError, TypeError):
        return resolve_latest_version(name, "npm")
    return match or None


def _looks_like_non_registry_spec(specifier: str) -> bool:
    s = specifier.strip().lower()
    return s.startswith(("git+", "git:", "http://", "https://", "file:", "npm:")) or "/" in s


def _resolve_pypi_match(name: str, specifier: str) -> str | None:
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version
    try:
        spec_set = SpecifierSet(specifier)
    except InvalidSpecifier:
        return resolve_latest_version(name, "pypi")
    data = _http_get_json(f"https://pypi.org/pypi/{name}/json")
    releases = data.get("releases") or {}
    parsed: list[Version] = []
    for raw in releases.keys():
        try:
            parsed.append(Version(raw))
        except InvalidVersion:
            continue
    matches = [v for v in parsed if v in spec_set and not v.is_prerelease]
    if not matches:
        matches = [v for v in parsed if v in spec_set]
    if not matches:
        return None
    return str(max(matches))


def parse_spec(raw: str, ecosystem_override: str | None = None) -> PackageSpec:
    ecosystem = ecosystem_override or _detect_ecosystem(raw)
    name, version = _split_name_and_version(raw, ecosystem)
    return PackageSpec(name=name, version=version, ecosystem=ecosystem)


def _detect_ecosystem(raw: str) -> str:
    if raw.startswith("@") or NPM_SCOPED_PATTERN.match(raw):
        return "npm"
    return "pypi"


def _split_name_and_version(raw: str, ecosystem: str) -> tuple[str, str | None]:
    if ecosystem == "npm":
        return _split_npm(raw)
    return _split_pypi(raw)


def _split_npm(raw: str) -> tuple[str, str | None]:
    if raw.startswith("@"):
        at_index = raw.find("@", 1)
        if at_index == -1:
            return raw, None
        return raw[:at_index], raw[at_index + 1:]
    if "@" in raw:
        name, _, version = raw.partition("@")
        return name, version
    return raw, None


def _split_pypi(raw: str) -> tuple[str, str | None]:
    match = PYPI_SPEC_PATTERN.match(raw)
    if not match:
        raise FetchError(f"invalid pypi spec: {raw}")
    return match.group(1), match.group(2)


def _cache_dir(spec: PackageSpec, cache_root: Path) -> Path:
    return cache_root / spec.ecosystem / spec.name / (spec.version or "unversioned") / "src"


def _has_unpacked_contents(path: Path) -> bool:
    return path.exists() and any(path.iterdir())


def _fetch_pypi(spec: PackageSpec, dest: Path) -> None:
    url, filename = _resolve_pypi_artifact(spec)
    archive = _download_to_staging(url, filename, dest)
    _unpack_into(archive, dest)
    shutil.rmtree(archive.parent, ignore_errors=True)


def _fetch_npm(spec: PackageSpec, dest: Path) -> None:
    url, filename = _resolve_npm_artifact(spec)
    archive = _download_to_staging(url, filename, dest)
    _unpack_into(archive, dest)
    shutil.rmtree(archive.parent, ignore_errors=True)


def _resolve_pypi_artifact(spec: PackageSpec) -> tuple[str, str]:
    metadata_url = f"https://pypi.org/pypi/{spec.name}/{spec.version}/json" if spec.version else f"https://pypi.org/pypi/{spec.name}/json"
    data = _http_get_json(metadata_url)
    urls = data.get("urls") or []
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = sdist or (urls[0] if urls else None)
    if not chosen or not chosen.get("url"):
        raise FetchError(f"no downloadable artifact for {spec.name}=={spec.version}")
    return chosen["url"], chosen.get("filename") or chosen["url"].rsplit("/", 1)[-1]


def _resolve_npm_artifact(spec: PackageSpec) -> tuple[str, str]:
    if not spec.version:
        meta = _http_get_json(f"https://registry.npmjs.org/{spec.name}")
        version = (meta.get("dist-tags") or {}).get("latest")
        if not version:
            raise FetchError(f"could not resolve latest version for {spec.name}")
    else:
        version = spec.version
    data = _http_get_json(f"https://registry.npmjs.org/{spec.name}/{version}")
    tarball = (data.get("dist") or {}).get("tarball")
    if not tarball:
        raise FetchError(f"no tarball for {spec.name}@{version}")
    return tarball, tarball.rsplit("/", 1)[-1]


def _http_get_json(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise FetchError(f"GET {url} failed: {exc}") from exc


def _download_to_staging(url: str, filename: str, dest: Path) -> Path:
    staging = dest.parent / "_download"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    archive = staging / filename
    try:
        with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)
    except urllib.error.URLError as exc:
        raise FetchError(f"download {url} failed: {exc}") from exc
    return archive


def _unpack_into(archive: Path, dest: Path) -> None:
    if archive.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tar:
            _safe_extract_tar(tar, dest)
    elif archive.suffix in {".whl", ".zip"}:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        raise FetchError(f"unsupported archive type: {archive.name}")


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest.resolve())):
            raise FetchError(f"archive contains escaping path: {member.name}")
    tar.extractall(dest, filter="data")


