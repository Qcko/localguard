import json
import tarfile
from pathlib import Path

import pytest

from localguard import fetch, hook, preflight


FIXTURES = Path(__file__).parent / "fixtures"


def test_extract_pip_install_basic():
    installs = hook.extract_installs("pip install requests httpx==0.27.0")
    assert len(installs) == 1
    assert installs[0].ecosystem == "pypi"
    assert installs[0].specs == ["requests", "httpx==0.27.0"]


def test_extract_uv_add():
    installs = hook.extract_installs("uv add fastapi pydantic")
    assert installs[0].ecosystem == "pypi"
    assert installs[0].specs == ["fastapi", "pydantic"]


def test_extract_uv_pip_install():
    installs = hook.extract_installs("uv pip install ruff")
    assert installs[0].ecosystem == "pypi"
    assert installs[0].specs == ["ruff"]


def test_extract_scoped_npm():
    installs = hook.extract_installs("npm install @modelcontextprotocol/server-filesystem")
    assert installs[0].ecosystem == "npm"
    assert installs[0].specs == ["@modelcontextprotocol/server-filesystem"]


def test_extract_pnpm_add_and_yarn_add():
    pnpm = hook.extract_installs("pnpm add left-pad")
    yarn = hook.extract_installs("yarn add lodash")
    assert pnpm[0].ecosystem == "npm" and pnpm[0].specs == ["left-pad"]
    assert yarn[0].ecosystem == "npm" and yarn[0].specs == ["lodash"]


def test_skips_requirements_file_and_editable():
    installs = hook.extract_installs("pip install -r requirements.txt -e .")
    assert installs == [] or installs[0].specs == []


def test_skips_local_path_install():
    installs = hook.extract_installs("pip install ./my-pkg ../other")
    assert installs == [] or installs[0].specs == []


def test_handles_chained_commands():
    installs = hook.extract_installs("uv add fastapi && pip install httpx")
    ecosystems = {i.ecosystem for i in installs}
    all_specs = [s for i in installs for s in i.specs]
    assert ecosystems == {"pypi"}
    assert sorted(all_specs) == ["fastapi", "httpx"]


def test_no_install_command_returns_empty():
    assert hook.extract_installs("ls -la") == []
    assert hook.extract_installs("npm run build") == []
    assert hook.extract_installs("npm install") == []  # no specs => skip


def test_hook_ignores_non_bash_tool(monkeypatch):
    payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}})
    code, out, err = hook.render_to_string(payload)
    assert code == 0
    assert out == "" and err == ""


def test_hook_allows_safe_install(tmp_path, monkeypatch):
    _seed_local_baseline(tmp_path, "clean-pkg", "0.1.0", FIXTURES / "clean_pkg")
    _patch_roots(monkeypatch, tmp_path)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install clean-pkg==0.1.0"}})
    code, out, err = hook.render_to_string(payload)
    assert code == 0
    assert "OK" in out
    assert "BLOCK" not in err


def test_hook_blocks_low_score_install(tmp_path, monkeypatch):
    _seed_cache_only(tmp_path, "drifty-pkg", "0.2.0", FIXTURES / "tampered_v2")
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "DEFAULT_MIN_SCORE", 80)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install drifty-pkg==0.2.0"}})
    code, out, err = hook.render_to_string(payload)
    assert code == 2
    assert "BLOCK" in err
    assert "drifty-pkg" in err


def _seed_local_baseline(tmp_path: Path, name: str, version: str, fixture: Path) -> None:
    _seed_cache_only(tmp_path, name, version, fixture)
    from localguard import audit, manifest
    report = audit.audit_path(fixture).to_dict()
    report["name"] = name
    report["version"] = version
    manifest.write_library_entry(report, library_root=tmp_path / "lib")


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
    from localguard import manifest
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    from localguard import preflight as pf
    monkeypatch.setattr(pf.fetch, "DEFAULT_CACHE_ROOT", cache_root)
    monkeypatch.setattr(pf.manifest, "DEFAULT_LIBRARY_ROOT", library_root)
