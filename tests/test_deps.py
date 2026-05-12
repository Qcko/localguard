import json
import tarfile
import textwrap
from pathlib import Path

from localguard import deps, fetch, manifest, preflight


FIXTURES = Path(__file__).parent / "fixtures"


def test_python_deps_from_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(textwrap.dedent("""
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = [
          "requests>=2.25.0",
          "urllib3 (>=1.21.1,<3)",
          "rich[markdown]>=13",
          "tomli; python_version < '3.11'",
          "pytest; extra == 'test'",
        ]
    """), encoding="utf-8")

    result = deps.extract_deps(tmp_path, "pypi")

    assert result == ["requests", "urllib3", "rich", "tomli"]


def test_python_deps_from_pkg_info_when_no_pyproject(tmp_path: Path):
    (tmp_path / "PKG-INFO").write_text(textwrap.dedent("""
        Metadata-Version: 2.1
        Name: demo
        Requires-Dist: requests>=2.25.0
        Requires-Dist: urllib3 (>=1.21.1,<3)
        Requires-Dist: pytest; extra == 'test'
    """), encoding="utf-8")

    result = deps.extract_deps(tmp_path, "pypi")

    assert result == ["requests", "urllib3"]


def test_python_deps_from_egg_info_requires_txt(tmp_path: Path):
    egg = tmp_path / "demo.egg-info"
    egg.mkdir()
    (egg / "requires.txt").write_text(textwrap.dedent("""
        charset_normalizer<4,>=2
        idna<4,>=2.5
        urllib3<3,>=1.21.1
        certifi>=2017.4.17

        [security]

        [socks]
        PySocks!=1.5.7,>=1.5.6
    """), encoding="utf-8")

    result = deps.extract_deps(tmp_path, "pypi")

    assert result == ["charset_normalizer", "idna", "urllib3", "certifi"]


def test_npm_deps_from_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo",
        "version": "0.1.0",
        "dependencies": {
            "@modelcontextprotocol/sdk": "^1.0.0",
            "zod": "^3.0.0",
        },
        "devDependencies": {"typescript": "^5"},
    }), encoding="utf-8")

    result = deps.extract_deps(tmp_path, "npm")

    assert result == ["@modelcontextprotocol/sdk", "zod"]


def test_extracts_nothing_when_no_metadata(tmp_path: Path):
    assert deps.extract_deps(tmp_path, "pypi") == []
    assert deps.extract_deps(tmp_path, "npm") == []


def test_audit_tree_recursive_clean(tmp_path: Path, monkeypatch):
    _seed_pkg(tmp_path, "parent", "1.0", deps=["child-a", "child-b"])
    _seed_pkg(tmp_path, "child-a", "0.1", deps=["leaf"])
    _seed_pkg(tmp_path, "child-b", "0.2", deps=[])
    _seed_pkg(tmp_path, "leaf", "9.9", deps=[])
    _baseline_all(tmp_path, ["parent==1.0", "child-a==0.1", "child-b==0.2", "leaf==9.9"])
    _stub_latest(monkeypatch, {"child-a": "0.1", "child-b": "0.2", "leaf": "9.9"})

    node = deps.audit_tree("parent==1.0", cache_root=tmp_path / "cache", library_root=tmp_path / "lib")

    assert node.composed_status == "safe"
    assert {c.name for c in node.children} == {"child-a", "child-b"}
    assert {gc.name for c in node.children for gc in c.children} == {"leaf"}


def test_audit_tree_blocks_via_unknown_child(tmp_path: Path, monkeypatch):
    _seed_pkg(tmp_path, "parent", "1.0", deps=["unknown-dep"])
    _seed_pkg(tmp_path, "unknown-dep", "2.0", deps=[])
    _baseline_all(tmp_path, ["parent==1.0"])
    _stub_latest(monkeypatch, {"unknown-dep": "2.0"})
    monkeypatch.setattr(preflight, "DEFAULT_AUTO_ACCEPT_SCORE", 101)

    node = deps.audit_tree("parent==1.0", cache_root=tmp_path / "cache", library_root=tmp_path / "lib")

    assert node.verdict.safe
    assert node.blocked is True
    assert node.composed_status.startswith("blocked-via:unknown-dep")


def test_audit_tree_auto_baselines_clean_high_score_nodes(tmp_path: Path, monkeypatch):
    _seed_pkg(tmp_path, "parent", "1.0", deps=["child"])
    _seed_pkg(tmp_path, "child", "2.0", deps=[])
    _stub_latest(monkeypatch, {"child": "2.0"})

    node = deps.audit_tree("parent==1.0", cache_root=tmp_path / "cache", library_root=tmp_path / "lib")

    assert node.composed_status == "safe"
    assert node.verdict.status == "first-encounter-accepted"
    assert node.children[0].verdict.status == "first-encounter-accepted"
    assert manifest.latest_known_good("parent", "pypi", library_root=tmp_path / "lib") is not None
    assert manifest.latest_known_good("child", "pypi", library_root=tmp_path / "lib") is not None


def test_audit_tree_detects_cycle(tmp_path: Path, monkeypatch):
    _seed_pkg(tmp_path, "a", "1.0", deps=["b"])
    _seed_pkg(tmp_path, "b", "1.0", deps=["a"])
    _baseline_all(tmp_path, ["a==1.0", "b==1.0"])
    _stub_latest(monkeypatch, {"a": "1.0", "b": "1.0"})

    node = deps.audit_tree("a==1.0", cache_root=tmp_path / "cache", library_root=tmp_path / "lib")

    cycle_nodes = _walk(node)
    assert any(n.cycle for n in cycle_nodes), "expected at least one cycle-marked node"


def test_audit_tree_max_depth_truncates(tmp_path: Path, monkeypatch):
    _seed_pkg(tmp_path, "root", "1.0", deps=["mid"])
    _seed_pkg(tmp_path, "mid", "1.0", deps=["leaf"])
    _seed_pkg(tmp_path, "leaf", "1.0", deps=[])
    _baseline_all(tmp_path, ["root==1.0", "mid==1.0", "leaf==1.0"])
    _stub_latest(monkeypatch, {"mid": "1.0", "leaf": "1.0"})

    node = deps.audit_tree("root==1.0", max_depth=1, cache_root=tmp_path / "cache", library_root=tmp_path / "lib")

    mid = node.children[0]
    assert mid.truncated is True
    assert mid.children == []


def _seed_pkg(tmp_path: Path, name: str, version: str, *, deps: list[str]) -> None:
    src = tmp_path / "cache" / "pypi" / name / version / "src" / f"{name}-{version}"
    src.mkdir(parents=True)
    deps_str = "[" + ", ".join(f'"{d}"' for d in deps) + "]"
    (src / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\ndependencies = {deps_str}\n',
        encoding="utf-8",
    )
    (src / "__init__.py").write_text("", encoding="utf-8")


def _baseline_all(tmp_path: Path, specs: list[str]) -> None:
    from localguard import audit
    library_root = tmp_path / "lib"
    library_root.mkdir(exist_ok=True)
    for raw in specs:
        name, _, version = raw.partition("==")
        src = tmp_path / "cache" / "pypi" / name / version / "src" / f"{name}-{version}"
        report = audit.audit_path(src).to_dict()
        report["name"] = name
        report["version"] = version
        report["ecosystem"] = "pypi"
        manifest.write_library_entry(report, library_root=library_root)


def _stub_latest(monkeypatch, mapping: dict[str, str]) -> None:
    def fake(name: str, ecosystem: str):
        return mapping.get(name)
    monkeypatch.setattr(fetch, "resolve_latest_version", fake)


def _walk(node):
    out = [node]
    for c in node.children:
        out.extend(_walk(c))
    return out


def test_parse_requirement_handles_edge_cases():
    assert deps.parse_requirement("requests>=2.25") == "requests"
    assert deps.parse_requirement("Requests") == "requests"
    assert deps.parse_requirement("rich[markdown]>=13") == "rich"
    assert deps.parse_requirement("urllib3 (>=1.21.1,<3)") == "urllib3"
    assert deps.parse_requirement("tomli; python_version < '3.11'") == "tomli"
    assert deps.parse_requirement("pytest; extra == 'test'") is None
    assert deps.parse_requirement("") is None
    assert deps.parse_requirement(";") is None
