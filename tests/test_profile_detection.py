from __future__ import annotations

from localguard import rubric
from localguard.report import Finding, SurfaceKind


def _mcp_tool(file: str) -> Finding:
    return Finding(kind=SurfaceKind.MCP_TOOL, file=file, line=1, detail="", confidence="literal", extra={})


def _mcp_resource(file: str) -> Finding:
    return Finding(kind=SurfaceKind.MCP_RESOURCE, file=file, line=1, detail="", confidence="literal", extra={})


def test_content_detection_fires_on_runtime_mcp_tool():
    result = rubric.detect_profile_from_content([_mcp_tool("server/tools.py")])
    assert result is not None
    assert result[0] == rubric.PROFILE_MCP_SERVER
    assert "mcp_tool/resource" in result[1]


def test_content_detection_ignores_test_dir_findings():
    findings = [_mcp_tool("tests/test_tools.py"), _mcp_resource("examples/demo.py")]
    assert rubric.detect_profile_from_content(findings) is None


def test_content_detection_returns_none_when_no_mcp_findings():
    from localguard.report import Finding, SurfaceKind
    findings = [Finding(kind=SurfaceKind.SUBPROCESS, file="x.py", line=1, detail="", confidence="literal", extra={})]
    assert rubric.detect_profile_from_content(findings) is None


def test_pypi_mcp_server_prefix_detected():
    assert rubric.detect_profile_from_name("mcp-server-filesystem", "pypi") == (
        rubric.PROFILE_MCP_SERVER, "name-convention: mcp-server-*",
    )


def test_pypi_canonical_form_after_pep503_works():
    # The canonical name (post-PEP 503) is what reaches detection.
    assert rubric.detect_profile_from_name("mcp-server-foo", "pypi") is not None


def test_npm_modelcontextprotocol_scope_detected():
    result = rubric.detect_profile_from_name("@modelcontextprotocol/server-filesystem", "npm")
    assert result == (rubric.PROFILE_MCP_SERVER, "name-convention: @modelcontextprotocol/server-*")


def test_npm_bare_mcp_server_prefix_detected():
    assert rubric.detect_profile_from_name("mcp-server-foo", "npm") is not None


def test_click_typer_etc_detect_as_cli_framework():
    assert rubric.detect_profile_from_name("click", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: click")
    assert rubric.detect_profile_from_name("typer", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: typer")
    assert rubric.detect_profile_from_name("fire", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: fire")


def test_metadata_detection_pypi_console_scripts(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""
[project]
name = "demo-cli"
version = "1.0"
[project.scripts]
demo = "demo.main:cli"
""", encoding="utf-8")
    assert rubric.detect_profile_from_metadata(tmp_path, "pypi") == (
        rubric.PROFILE_CLI_FRAMEWORK, "metadata: 1 console-script entry point(s)",
    )


def test_metadata_detection_pypi_no_scripts(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""
[project]
name = "demo"
version = "1.0"
""", encoding="utf-8")
    assert rubric.detect_profile_from_metadata(tmp_path, "pypi") is None


def test_metadata_detection_npm_bin(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo","version":"1.0","bin":{"demo":"./cli.js","demo-x":"./xcli.js"}}', encoding="utf-8")
    result = rubric.detect_profile_from_metadata(tmp_path, "npm")
    assert result == (rubric.PROFILE_CLI_FRAMEWORK, "metadata: 2 bin entry point(s)")


def test_metadata_detection_npm_string_bin(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo","version":"1.0","bin":"./cli.js"}', encoding="utf-8")
    result = rubric.detect_profile_from_metadata(tmp_path, "npm")
    assert result == (rubric.PROFILE_CLI_FRAMEWORK, "metadata: 1 bin entry point(s)")


def test_requests_httpx_etc_detect_as_network_library():
    assert rubric.detect_profile_from_name("requests", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: requests",
    )
    assert rubric.detect_profile_from_name("httpx", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: httpx",
    )
    assert rubric.detect_profile_from_name("urllib3", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: urllib3",
    )
    assert rubric.detect_profile_from_name("aiohttp", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: aiohttp",
    )


def test_uvicorn_gunicorn_etc_detect_as_web_server():
    assert rubric.detect_profile_from_name("uvicorn", "pypi") == (
        rubric.PROFILE_WEB_SERVER, "name-allowlist: uvicorn",
    )
    assert rubric.detect_profile_from_name("gunicorn", "pypi") == (
        rubric.PROFILE_WEB_SERVER, "name-allowlist: gunicorn",
    )
    assert rubric.detect_profile_from_name("hypercorn", "pypi") == (
        rubric.PROFILE_WEB_SERVER, "name-allowlist: hypercorn",
    )
    assert rubric.detect_profile_from_name("granian", "pypi") == (
        rubric.PROFILE_WEB_SERVER, "name-allowlist: granian",
    )


def test_setuptools_wheel_etc_detect_as_build_tool():
    assert rubric.detect_profile_from_name("setuptools", "pypi") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: setuptools",
    )
    assert rubric.detect_profile_from_name("wheel", "pypi") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: wheel",
    )
    assert rubric.detect_profile_from_name("hatchling", "pypi") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: hatchling",
    )
    assert rubric.detect_profile_from_name("poetry-core", "pypi") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: poetry-core",
    )
    assert rubric.detect_profile_from_name("maturin", "pypi") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: maturin",
    )


def test_numpy_pandas_etc_detect_as_data_science():
    assert rubric.detect_profile_from_name("numpy", "pypi") == (
        rubric.PROFILE_DATA_SCIENCE, "name-allowlist: numpy",
    )
    assert rubric.detect_profile_from_name("pandas", "pypi") == (
        rubric.PROFILE_DATA_SCIENCE, "name-allowlist: pandas",
    )
    assert rubric.detect_profile_from_name("scikit-learn", "pypi") == (
        rubric.PROFILE_DATA_SCIENCE, "name-allowlist: scikit-learn",
    )
    assert rubric.detect_profile_from_name("matplotlib", "pypi") == (
        rubric.PROFILE_DATA_SCIENCE, "name-allowlist: matplotlib",
    )


def test_torch_transformers_etc_detect_as_ml_framework():
    assert rubric.detect_profile_from_name("torch", "pypi") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: torch",
    )
    assert rubric.detect_profile_from_name("tensorflow", "pypi") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: tensorflow",
    )
    assert rubric.detect_profile_from_name("transformers", "pypi") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: transformers",
    )
    assert rubric.detect_profile_from_name("jax", "pypi") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: jax",
    )
    assert rubric.detect_profile_from_name("huggingface-hub", "pypi") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: huggingface-hub",
    )


def test_sqlalchemy_pymongo_etc_detect_as_database_driver():
    assert rubric.detect_profile_from_name("sqlalchemy", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: sqlalchemy",
    )
    assert rubric.detect_profile_from_name("psycopg2-binary", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: psycopg2-binary",
    )
    assert rubric.detect_profile_from_name("pymongo", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: pymongo",
    )
    assert rubric.detect_profile_from_name("redis", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: redis",
    )
    assert rubric.detect_profile_from_name("kafka-python", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: kafka-python",
    )


def test_jinja2_mako_etc_detect_as_template_engine():
    assert rubric.detect_profile_from_name("jinja2", "pypi") == (
        rubric.PROFILE_TEMPLATE_ENGINE, "name-allowlist: jinja2",
    )
    assert rubric.detect_profile_from_name("mako", "pypi") == (
        rubric.PROFILE_TEMPLATE_ENGINE, "name-allowlist: mako",
    )
    assert rubric.detect_profile_from_name("chevron", "pypi") == (
        rubric.PROFILE_TEMPLATE_ENGINE, "name-allowlist: chevron",
    )


def test_pytest_hypothesis_etc_detect_as_test_framework():
    assert rubric.detect_profile_from_name("pytest", "pypi") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: pytest",
    )
    assert rubric.detect_profile_from_name("hypothesis", "pypi") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: hypothesis",
    )
    assert rubric.detect_profile_from_name("coverage", "pypi") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: coverage",
    )
    assert rubric.detect_profile_from_name("tox", "pypi") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: tox",
    )


def test_boto3_azure_etc_detect_as_cloud_sdk():
    assert rubric.detect_profile_from_name("boto3", "pypi") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: boto3",
    )
    assert rubric.detect_profile_from_name("botocore", "pypi") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: botocore",
    )
    assert rubric.detect_profile_from_name("google-auth", "pypi") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: google-auth",
    )
    assert rubric.detect_profile_from_name("azure-identity", "pypi") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: azure-identity",
    )
    assert rubric.detect_profile_from_name("kubernetes", "pypi") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: kubernetes",
    )


def test_sentry_otel_etc_detect_as_observability():
    assert rubric.detect_profile_from_name("sentry-sdk", "pypi") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: sentry-sdk",
    )
    assert rubric.detect_profile_from_name("opentelemetry-sdk", "pypi") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: opentelemetry-sdk",
    )
    assert rubric.detect_profile_from_name("ddtrace", "pypi") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: ddtrace",
    )
    assert rubric.detect_profile_from_name("structlog", "pypi") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: structlog",
    )


def test_pillow_lxml_etc_detect_as_format_codec():
    assert rubric.detect_profile_from_name("pillow", "pypi") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: pillow",
    )
    assert rubric.detect_profile_from_name("lxml", "pypi") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: lxml",
    )
    assert rubric.detect_profile_from_name("openpyxl", "pypi") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: openpyxl",
    )
    assert rubric.detect_profile_from_name("pypdf", "pypi") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: pypdf",
    )
    assert rubric.detect_profile_from_name("markdown", "pypi") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: markdown",
    )


def test_scrapy_selenium_etc_detect_as_scraping():
    assert rubric.detect_profile_from_name("scrapy", "pypi") == (
        rubric.PROFILE_SCRAPING, "name-allowlist: scrapy",
    )
    assert rubric.detect_profile_from_name("selenium", "pypi") == (
        rubric.PROFILE_SCRAPING, "name-allowlist: selenium",
    )
    assert rubric.detect_profile_from_name("playwright", "pypi") == (
        rubric.PROFILE_SCRAPING, "name-allowlist: playwright",
    )


def test_django_fastapi_etc_detect_as_web_framework():
    assert rubric.detect_profile_from_name("django", "pypi") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: django",
    )
    assert rubric.detect_profile_from_name("fastapi", "pypi") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: fastapi",
    )
    assert rubric.detect_profile_from_name("flask", "pypi") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: flask",
    )
    assert rubric.detect_profile_from_name("tornado", "pypi") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: tornado",
    )


def test_twisted_gevent_etc_detect_as_async_runtime():
    assert rubric.detect_profile_from_name("twisted", "pypi") == (
        rubric.PROFILE_ASYNC_RUNTIME, "name-allowlist: twisted",
    )
    assert rubric.detect_profile_from_name("gevent", "pypi") == (
        rubric.PROFILE_ASYNC_RUNTIME, "name-allowlist: gevent",
    )
    assert rubric.detect_profile_from_name("trio", "pypi") == (
        rubric.PROFILE_ASYNC_RUNTIME, "name-allowlist: trio",
    )


def test_celery_rq_etc_detect_as_task_queue():
    assert rubric.detect_profile_from_name("celery", "pypi") == (
        rubric.PROFILE_TASK_QUEUE, "name-allowlist: celery",
    )
    assert rubric.detect_profile_from_name("rq", "pypi") == (
        rubric.PROFILE_TASK_QUEUE, "name-allowlist: rq",
    )
    assert rubric.detect_profile_from_name("dramatiq", "pypi") == (
        rubric.PROFILE_TASK_QUEUE, "name-allowlist: dramatiq",
    )


def test_ipython_jupyter_etc_detect_as_notebook_runtime():
    assert rubric.detect_profile_from_name("ipython", "pypi") == (
        rubric.PROFILE_NOTEBOOK_RUNTIME, "name-allowlist: ipython",
    )
    assert rubric.detect_profile_from_name("jupyterlab", "pypi") == (
        rubric.PROFILE_NOTEBOOK_RUNTIME, "name-allowlist: jupyterlab",
    )
    assert rubric.detect_profile_from_name("ipykernel", "pypi") == (
        rubric.PROFILE_NOTEBOOK_RUNTIME, "name-allowlist: ipykernel",
    )
    assert rubric.detect_profile_from_name("nbconvert", "pypi") == (
        rubric.PROFILE_NOTEBOOK_RUNTIME, "name-allowlist: nbconvert",
    )


def test_normal_libraries_are_not_detected():
    assert rubric.detect_profile_from_name("lodash", "npm") is None
    assert rubric.detect_profile_from_name("mcp", "pypi") is None  # the SDK itself: library, not server
    assert rubric.detect_profile_from_name("@modelcontextprotocol/sdk", "npm") is None
    assert rubric.detect_profile_from_name("pyyaml", "pypi") is None


def test_empty_or_unknown_ecosystem_returns_none():
    assert rubric.detect_profile_from_name("", "pypi") is None
    assert rubric.detect_profile_from_name("mcp-server-foo", "unknown") is None
