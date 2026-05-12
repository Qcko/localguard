from localguard import fetch


def _stub_pypi_json(monkeypatch, releases: dict) -> None:
    def fake_get(url: str):
        return {"info": {"version": "9.9.9"}, "releases": releases}
    monkeypatch.setattr(fetch, "_http_get_json", fake_get)


def test_resolve_matching_picks_highest_in_range(monkeypatch):
    _stub_pypi_json(monkeypatch, {"1.0.0": [], "2.0.0": [], "2.5.1": [], "3.0.0": []})
    result = fetch.resolve_matching_version("demo", "pypi", ">=2.0,<3")
    assert result == "2.5.1"


def test_resolve_matching_excludes_prereleases_by_default(monkeypatch):
    _stub_pypi_json(monkeypatch, {"1.0.0": [], "2.0.0": [], "2.1.0a1": [], "2.1.0rc1": []})
    result = fetch.resolve_matching_version("demo", "pypi", ">=2.0")
    assert result == "2.0.0"


def test_resolve_matching_falls_back_to_prerelease_if_only_option(monkeypatch):
    _stub_pypi_json(monkeypatch, {"2.0.0a1": [], "2.0.0a2": []})
    result = fetch.resolve_matching_version("demo", "pypi", ">=2.0.0a1")
    assert result == "2.0.0a2"


def test_resolve_matching_empty_specifier_uses_latest(monkeypatch):
    monkeypatch.setattr(fetch, "_http_get_json", lambda url: {"info": {"version": "7.7.7"}, "releases": {}})
    assert fetch.resolve_matching_version("demo", "pypi", None) == "7.7.7"
    assert fetch.resolve_matching_version("demo", "pypi", "") == "7.7.7"
    assert fetch.resolve_matching_version("demo", "pypi", "*") == "7.7.7"


def test_resolve_matching_invalid_specifier_falls_back_to_latest(monkeypatch):
    monkeypatch.setattr(fetch, "_http_get_json", lambda url: {"info": {"version": "1.2.3"}, "releases": {"1.2.3": []}})
    assert fetch.resolve_matching_version("demo", "pypi", "not-a-spec") == "1.2.3"


def test_resolve_matching_no_version_in_range(monkeypatch):
    _stub_pypi_json(monkeypatch, {"1.0.0": [], "2.0.0": []})
    assert fetch.resolve_matching_version("demo", "pypi", ">=3.0") is None


def _stub_npm_registry(monkeypatch, versions: list[str], latest: str | None = None) -> None:
    payload = {
        "dist-tags": {"latest": latest or (versions[-1] if versions else "")},
        "versions": {v: {} for v in versions},
    }
    monkeypatch.setattr(fetch, "_http_get_json", lambda url: payload)


def test_resolve_matching_npm_caret_range(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.0.0", "1.5.2", "1.9.9", "2.0.0", "2.1.0"])
    assert fetch.resolve_matching_version("demo", "npm", "^1.0.0") == "1.9.9"


def test_resolve_matching_npm_tilde_range(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.2.0", "1.2.5", "1.2.9", "1.3.0"])
    assert fetch.resolve_matching_version("demo", "npm", "~1.2.0") == "1.2.9"


def test_resolve_matching_npm_explicit_range(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.0.0", "2.0.0", "2.5.0", "3.0.0"])
    assert fetch.resolve_matching_version("demo", "npm", ">=2.0.0 <3.0.0") == "2.5.0"


def test_resolve_matching_npm_latest_dist_tag(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.0.0", "1.5.0"], latest="1.5.0")
    assert fetch.resolve_matching_version("demo", "npm", "latest") == "1.5.0"


def test_resolve_matching_npm_git_url_falls_back_to_latest(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.0.0", "2.0.0"], latest="2.0.0")
    assert fetch.resolve_matching_version("demo", "npm", "git+https://github.com/foo/bar.git") == "2.0.0"


def test_resolve_matching_npm_no_matching_version(monkeypatch):
    _stub_npm_registry(monkeypatch, ["1.0.0", "1.5.0"])
    assert fetch.resolve_matching_version("demo", "npm", "^5.0.0") is None
