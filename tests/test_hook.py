import json
import tarfile
from pathlib import Path

import pytest

from localguard import deps, fetch, hook, preflight


FIXTURES = Path(__file__).parent / "fixtures"


def test_extract_uvx_applies_mcp_server_profile():
    installs = hook.extract_installs("uvx mcp-server-foo")
    assert len(installs) == 1
    assert installs[0].ecosystem == "pypi"
    assert installs[0].specs == ["mcp-server-foo"]
    assert installs[0].profile_hint == "mcp-server"
    assert installs[0].profile_reason == "install-verb: uvx"


def test_extract_pipx_install_applies_mcp_server_profile():
    installs = hook.extract_installs("pipx install some-cli")
    assert installs[0].profile_hint == "mcp-server"
    assert installs[0].profile_reason == "install-verb: pipx install"


def test_extract_uv_tool_install_applies_mcp_server_profile():
    installs = hook.extract_installs("uv tool install ruff")
    assert installs[0].ecosystem == "pypi"
    assert installs[0].specs == ["ruff"]
    assert installs[0].profile_hint == "mcp-server"
    assert installs[0].profile_reason == "install-verb: uv tool install"


def test_extract_npx_yes_applies_mcp_server_profile():
    installs = hook.extract_installs("npx -y @modelcontextprotocol/server-filesystem")
    assert installs[0].ecosystem == "npm"
    assert installs[0].specs == ["@modelcontextprotocol/server-filesystem"]
    assert installs[0].profile_hint == "mcp-server"


def test_extract_npx_without_yes_is_not_classified():
    # npx without -y prompts interactively; don't apply profile/auto-install.
    installs = hook.extract_installs("npx @modelcontextprotocol/server-filesystem")
    assert installs == []


def test_extract_plain_install_has_no_profile_hint():
    installs = hook.extract_installs("pip install requests")
    assert installs[0].profile_hint is None
    assert installs[0].profile_reason is None


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


def test_does_not_capture_packages_from_piped_commands():
    installs = hook.extract_installs("uv add tree-sitter 2>&1 | tail -10")
    all_specs = [s for i in installs for s in i.specs]
    assert all_specs == ["tree-sitter"]


def test_stops_at_shell_redirection():
    installs = hook.extract_installs("pip install requests > /tmp/log.txt")
    all_specs = [s for i in installs for s in i.specs]
    assert all_specs == ["requests"]


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


def test_hook_fails_closed_on_preflight_exception(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("network down")
    monkeypatch.setattr(deps, "audit_tree", boom)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install ghost==9.9.9"}})
    code, _out, err = hook.render_to_string(payload)
    assert code == 2
    assert "preflight error" in err
    assert "ghost" in err


def test_hook_strict_mode_blocks_first_encounter(tmp_path, monkeypatch):
    _seed_cache_only(tmp_path, "clean-pkg", "0.1.0", FIXTURES / "clean_pkg")
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "DEFAULT_AUTO_ACCEPT_SCORE", 101)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install clean-pkg==0.1.0"}})
    code, out, err = hook.render_to_string(payload)
    assert code == 2
    assert "first-encounter-needs-accept" in err
    assert "localguard accept" in err


def test_hook_blocks_low_score_install(tmp_path, monkeypatch):
    _seed_cache_only(tmp_path, "drifty-pkg", "0.2.0", FIXTURES / "tampered_v2")
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "DEFAULT_MIN_SCORE", 80)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install drifty-pkg==0.2.0"}})
    code, out, err = hook.render_to_string(payload)
    assert code == 2
    assert "BLOCK" in err
    assert "drifty-pkg" in err
    # New: block message surfaces the library-status decision and the
    # role-typical share, plus an actionable `localguard accept` hint.
    assert ("blocked-role-typical" in err) or ("blocked-suspicious" in err)
    assert "role_typical_share=" in err
    assert "localguard accept" in err


def test_hook_blocks_via_unknown_transitive_dep(tmp_path, monkeypatch):
    _seed_local_baseline(tmp_path, "parent-pkg", "1.0", FIXTURES / "clean_pkg")
    _seed_synthetic_dep(tmp_path, "parent-pkg", "1.0", deps=["mystery-dep"])
    _seed_synthetic_dep(tmp_path, "mystery-dep", "0.1", deps=[])
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(fetch, "resolve_latest_version", lambda name, ecosystem: "0.1" if name == "mystery-dep" else None)
    monkeypatch.setattr(preflight, "DEFAULT_AUTO_ACCEPT_SCORE", 101)

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install parent-pkg==1.0"}})
    code, _out, err = hook.render_to_string(payload)

    assert code == 2
    assert "blocked-via:mystery-dep" in err
    assert "mystery-dep" in err
    assert "accept --with-deps" in err


def test_extract_uv_sync_reads_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\n'
        'dependencies = ["numpy>=2.0", "silero-vad", "faster-whisper==1.0.0"]\n'
        '[project.optional-dependencies]\n'
        'gpu = ["torch>=2.0"]\n'
        '[dependency-groups]\n'
        'dev = ["pytest"]\n',
        encoding="utf-8",
    )
    installs = hook.extract_installs("uv sync", cwd=str(tmp_path))
    assert len(installs) == 1
    assert installs[0].ecosystem == "pypi"
    assert sorted(installs[0].specs) == ["faster-whisper", "numpy", "pytest", "silero-vad", "torch"]
    assert installs[0].profile_reason == "install-verb: uv sync"


def test_extract_uv_lock_reads_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\ndependencies = ["requests"]\n',
        encoding="utf-8",
    )
    installs = hook.extract_installs("uv lock", cwd=str(tmp_path))
    assert installs[0].specs == ["requests"]


def test_extract_uv_sync_walks_up_to_find_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\ndependencies = ["httpx"]\n',
        encoding="utf-8",
    )
    nested = tmp_path / "sub" / "deeper"
    nested.mkdir(parents=True)
    installs = hook.extract_installs("uv sync", cwd=str(nested))
    assert installs[0].specs == ["httpx"]


def test_extract_uv_sync_blocks_when_pyproject_missing(tmp_path):
    installs = hook.extract_installs("uv sync", cwd=str(tmp_path))
    assert len(installs) == 1
    assert installs[0].specs == []
    assert installs[0].block_reason is not None
    assert "pyproject.toml" in installs[0].block_reason


def test_extract_uv_pip_sync_reads_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment line\n"
        "\n"
        "requests==2.31.0\n"
        "httpx>=0.27\n"
        "pandas; python_version>='3.10'\n"
        "-e ./local-pkg\n",
        encoding="utf-8",
    )
    installs = hook.extract_installs("uv pip sync requirements.txt", cwd=str(tmp_path))
    assert len(installs) == 1
    assert sorted(installs[0].specs) == ["httpx", "pandas", "requests"]
    assert installs[0].profile_reason == "install-verb: uv pip sync"


def test_extract_uv_pip_sync_recurses_includes(tmp_path):
    (tmp_path / "base.txt").write_text("flask\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("-r base.txt\nsqlalchemy\n", encoding="utf-8")
    installs = hook.extract_installs("uv pip sync requirements.txt", cwd=str(tmp_path))
    assert sorted(installs[0].specs) == ["flask", "sqlalchemy"]


def test_extract_uv_pip_sync_blocks_when_file_missing(tmp_path):
    installs = hook.extract_installs("uv pip sync ghost.txt", cwd=str(tmp_path))
    assert installs[0].specs == []
    assert installs[0].block_reason is not None
    assert "not readable" in installs[0].block_reason


def test_extract_uv_pip_sync_blocks_with_no_file_arg():
    installs = hook.extract_installs("uv pip sync")
    assert installs[0].specs == []
    assert "without a requirements file" in installs[0].block_reason


def test_extract_uv_pip_sync_multiple_files(tmp_path):
    (tmp_path / "a.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("beta\n", encoding="utf-8")
    installs = hook.extract_installs("uv pip sync a.txt b.txt", cwd=str(tmp_path))
    assert sorted(installs[0].specs) == ["alpha", "beta"]


def test_extract_uv_sync_honors_project_flag(tmp_path):
    proj = tmp_path / "elsewhere"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\ndependencies = ["flask"]\n',
        encoding="utf-8",
    )
    installs = hook.extract_installs(f"uv sync --project {proj}", cwd=str(tmp_path))
    assert installs[0].specs == ["flask"]


def test_extract_uv_sync_with_empty_deps_is_skipped(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\ndependencies = []\n',
        encoding="utf-8",
    )
    assert hook.extract_installs("uv sync", cwd=str(tmp_path)) == []


def test_hook_runs_for_powershell_tool(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("network down")
    monkeypatch.setattr(deps, "audit_tree", boom)
    payload = json.dumps({
        "tool_name": "PowerShell",
        "tool_input": {"command": "pip install ghost==9.9.9"},
    })
    code, _out, err = hook.render_to_string(payload)
    assert code == 2
    assert "ghost" in err


def test_hook_blocks_uv_sync_without_pyproject(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "uv sync"},
        "cwd": str(tmp_path),
    })
    code, _out, err = hook.render_to_string(payload)
    assert code == 2
    assert "BLOCK" in err
    assert "pyproject.toml" in err


def _seed_synthetic_dep(tmp_path: Path, name: str, version: str, *, deps: list) -> None:
    src = tmp_path / "cache" / "pypi" / name / version / "src" / f"{name}-{version}"
    src.mkdir(parents=True, exist_ok=True)
    deps_str = "[" + ", ".join(f'"{d}"' for d in deps) + "]"
    (src / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\ndependencies = {deps_str}\n',
        encoding="utf-8",
    )
    (src / "__init__.py").write_text("", encoding="utf-8")


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
