import json
import textwrap
from pathlib import Path

from localguard import deps


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


def test_parse_requirement_handles_edge_cases():
    assert deps.parse_requirement("requests>=2.25") == "requests"
    assert deps.parse_requirement("Requests") == "requests"
    assert deps.parse_requirement("rich[markdown]>=13") == "rich"
    assert deps.parse_requirement("urllib3 (>=1.21.1,<3)") == "urllib3"
    assert deps.parse_requirement("tomli; python_version < '3.11'") == "tomli"
    assert deps.parse_requirement("pytest; extra == 'test'") is None
    assert deps.parse_requirement("") is None
    assert deps.parse_requirement(";") is None
