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


def test_resolve_matching_npm_specifier_passthrough_to_latest(monkeypatch):
    monkeypatch.setattr(fetch, "_http_get_json", lambda url: {"dist-tags": {"latest": "4.2.0"}})
    assert fetch.resolve_matching_version("demo", "npm", "^4.0.0") == "4.2.0"
