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


def test_ruff_uv_detect_as_cli_framework():
    # Rust-shim CLIs ship no [project.scripts] so metadata detection misses
    # them; the name allowlist is the only signal that catches them.
    assert rubric.detect_profile_from_name("ruff", "pypi") == (
        rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: ruff",
    )
    assert rubric.detect_profile_from_name("uv", "pypi") == (
        rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: uv",
    )


def test_mcp_sdk_detected_as_mcp_server():
    # The flagship Python MCP SDK ships a `mcp dev` console script, which
    # would otherwise route through metadata detection as cli-framework.
    # The name allowlist beats that signal in priority order.
    assert rubric.detect_profile_from_name("mcp", "pypi") == (
        rubric.PROFILE_MCP_SERVER, "name-allowlist: mcp (mcp sdk)",
    )
    assert rubric.detect_profile_from_name("fastmcp", "pypi") == (
        rubric.PROFILE_MCP_SERVER, "name-allowlist: fastmcp (mcp sdk)",
    )


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


def test_gradio_streamlit_etc_detect_as_data_app():
    assert rubric.detect_profile_from_name("gradio", "pypi") == (
        rubric.PROFILE_DATA_APP, "name-allowlist: gradio",
    )
    assert rubric.detect_profile_from_name("streamlit", "pypi") == (
        rubric.PROFILE_DATA_APP, "name-allowlist: streamlit",
    )
    assert rubric.detect_profile_from_name("dash", "pypi") == (
        rubric.PROFILE_DATA_APP, "name-allowlist: dash",
    )
    assert rubric.detect_profile_from_name("nicegui", "pypi") == (
        rubric.PROFILE_DATA_APP, "name-allowlist: nicegui",
    )


def test_airflow_prefect_etc_detect_as_workflow_orchestrator():
    assert rubric.detect_profile_from_name("airflow", "pypi") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: airflow",
    )
    assert rubric.detect_profile_from_name("prefect", "pypi") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: prefect",
    )
    assert rubric.detect_profile_from_name("dagster", "pypi") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: dagster",
    )
    assert rubric.detect_profile_from_name("luigi", "pypi") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: luigi",
    )


def test_sphinx_mkdocs_etc_detect_as_doc_builder():
    assert rubric.detect_profile_from_name("sphinx", "pypi") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: sphinx",
    )
    assert rubric.detect_profile_from_name("mkdocs", "pypi") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: mkdocs",
    )
    assert rubric.detect_profile_from_name("myst-parser", "pypi") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: myst-parser",
    )


def test_langchain_llamaindex_etc_detect_as_agentic_framework():
    assert rubric.detect_profile_from_name("langchain", "pypi") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: langchain",
    )
    assert rubric.detect_profile_from_name("llama-index", "pypi") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: llama-index",
    )
    assert rubric.detect_profile_from_name("crewai", "pypi") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: crewai",
    )
    assert rubric.detect_profile_from_name("dspy", "pypi") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: dspy",
    )


def test_kivy_pyqt_etc_detect_as_gui_toolkit():
    assert rubric.detect_profile_from_name("kivy", "pypi") == (
        rubric.PROFILE_GUI_TOOLKIT, "name-allowlist: kivy",
    )
    assert rubric.detect_profile_from_name("pyqt6", "pypi") == (
        rubric.PROFILE_GUI_TOOLKIT, "name-allowlist: pyqt6",
    )
    assert rubric.detect_profile_from_name("wxpython", "pypi") == (
        rubric.PROFILE_GUI_TOOLKIT, "name-allowlist: wxpython",
    )


def test_chromadb_pinecone_etc_detect_as_database_driver():
    assert rubric.detect_profile_from_name("chromadb", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: chromadb",
    )
    assert rubric.detect_profile_from_name("weaviate-client", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: weaviate-client",
    )
    assert rubric.detect_profile_from_name("lancedb", "pypi") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: lancedb",
    )


def test_npm_express_fastify_etc_detect_as_web_framework():
    assert rubric.detect_profile_from_name("express", "npm") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: express",
    )
    assert rubric.detect_profile_from_name("fastify", "npm") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: fastify",
    )
    assert rubric.detect_profile_from_name("@nestjs/core", "npm") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: @nestjs/core",
    )
    assert rubric.detect_profile_from_name("next", "npm") == (
        rubric.PROFILE_WEB_FRAMEWORK, "name-allowlist: next",
    )


def test_npm_axios_node_fetch_etc_detect_as_network_library():
    assert rubric.detect_profile_from_name("axios", "npm") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: axios",
    )
    assert rubric.detect_profile_from_name("got", "npm") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: got",
    )
    assert rubric.detect_profile_from_name("node-fetch", "npm") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: node-fetch",
    )


def test_npm_webpack_swc_detect_as_build_tool():
    """Pure compilers/bundlers (no dev server) resolve to build-tool."""
    assert rubric.detect_profile_from_name("webpack", "npm") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: webpack",
    )
    assert rubric.detect_profile_from_name("@swc/core", "npm") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: @swc/core",
    )
    assert rubric.detect_profile_from_name("rollup", "npm") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: rollup",
    )
    assert rubric.detect_profile_from_name("esbuild", "npm") == (
        rubric.PROFILE_BUILD_TOOL, "name-allowlist: esbuild",
    )


def test_npm_vite_parcel_snowpack_detect_as_dev_server_bundler():
    """Bundlers that also run dev servers resolve to dev-server-bundler so
    their dev-server listening_port findings don't sink the score."""
    assert rubric.detect_profile_from_name("vite", "npm") == (
        rubric.PROFILE_DEV_SERVER_BUNDLER, "name-allowlist: vite",
    )
    assert rubric.detect_profile_from_name("parcel", "npm") == (
        rubric.PROFILE_DEV_SERVER_BUNDLER, "name-allowlist: parcel",
    )
    assert rubric.detect_profile_from_name("@parcel/core", "npm") == (
        rubric.PROFILE_DEV_SERVER_BUNDLER, "name-allowlist: @parcel/core",
    )
    assert rubric.detect_profile_from_name("snowpack", "npm") == (
        rubric.PROFILE_DEV_SERVER_BUNDLER, "name-allowlist: snowpack",
    )
    assert rubric.detect_profile_from_name("webpack-dev-server", "npm") == (
        rubric.PROFILE_DEV_SERVER_BUNDLER, "name-allowlist: webpack-dev-server",
    )


def test_npm_aws_sdk_scoped_detects_as_cloud_sdk():
    """Scoped @aws-sdk/* packages should all resolve via prefix match."""
    assert rubric.detect_profile_from_name("@aws-sdk/client-s3", "npm") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: @aws-sdk/client-s3",
    )
    assert rubric.detect_profile_from_name("@aws-sdk/client-dynamodb", "npm") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: @aws-sdk/client-dynamodb",
    )
    assert rubric.detect_profile_from_name("@azure/identity", "npm") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: @azure/identity",
    )
    assert rubric.detect_profile_from_name("@google-cloud/storage", "npm") == (
        rubric.PROFILE_CLOUD_SDK, "name-allowlist: @google-cloud/storage",
    )


def test_npm_sentry_opentelemetry_scoped_detect_as_observability():
    assert rubric.detect_profile_from_name("@sentry/node", "npm") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: @sentry/node",
    )
    assert rubric.detect_profile_from_name("@opentelemetry/api", "npm") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: @opentelemetry/api",
    )
    assert rubric.detect_profile_from_name("winston", "npm") == (
        rubric.PROFILE_OBSERVABILITY, "name-allowlist: winston",
    )


def test_npm_langchain_ai_etc_detect_as_agentic_framework():
    assert rubric.detect_profile_from_name("langchain", "npm") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: langchain",
    )
    assert rubric.detect_profile_from_name("@langchain/core", "npm") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: @langchain/core",
    )
    assert rubric.detect_profile_from_name("ai", "npm") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: ai",
    )
    assert rubric.detect_profile_from_name("openai", "npm") == (
        rubric.PROFILE_AGENTIC_FRAMEWORK, "name-allowlist: openai",
    )


def test_npm_jest_vitest_etc_detect_as_test_framework():
    assert rubric.detect_profile_from_name("jest", "npm") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: jest",
    )
    assert rubric.detect_profile_from_name("vitest", "npm") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: vitest",
    )
    assert rubric.detect_profile_from_name("mocha", "npm") == (
        rubric.PROFILE_TEST_FRAMEWORK, "name-allowlist: mocha",
    )


def test_npm_mongoose_prisma_etc_detect_as_database_driver():
    assert rubric.detect_profile_from_name("mongoose", "npm") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: mongoose",
    )
    assert rubric.detect_profile_from_name("@prisma/client", "npm") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: @prisma/client",
    )
    assert rubric.detect_profile_from_name("ioredis", "npm") == (
        rubric.PROFILE_DATABASE_DRIVER, "name-allowlist: ioredis",
    )


def test_npm_puppeteer_playwright_detect_as_scraping():
    assert rubric.detect_profile_from_name("puppeteer", "npm") == (
        rubric.PROFILE_SCRAPING, "name-allowlist: puppeteer",
    )
    assert rubric.detect_profile_from_name("playwright", "npm") == (
        rubric.PROFILE_SCRAPING, "name-allowlist: playwright",
    )


def test_npm_sharp_marked_etc_detect_as_format_codec():
    assert rubric.detect_profile_from_name("sharp", "npm") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: sharp",
    )
    assert rubric.detect_profile_from_name("marked", "npm") == (
        rubric.PROFILE_FORMAT_CODEC, "name-allowlist: marked",
    )


def test_npm_commander_yargs_etc_detect_as_cli_framework():
    assert rubric.detect_profile_from_name("commander", "npm") == (
        rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: commander",
    )
    assert rubric.detect_profile_from_name("yargs", "npm") == (
        rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: yargs",
    )


def test_npm_handlebars_pug_etc_detect_as_template_engine():
    assert rubric.detect_profile_from_name("handlebars", "npm") == (
        rubric.PROFILE_TEMPLATE_ENGINE, "name-allowlist: handlebars",
    )
    assert rubric.detect_profile_from_name("pug", "npm") == (
        rubric.PROFILE_TEMPLATE_ENGINE, "name-allowlist: pug",
    )


def test_npm_bull_bullmq_etc_detect_as_task_queue():
    assert rubric.detect_profile_from_name("bullmq", "npm") == (
        rubric.PROFILE_TASK_QUEUE, "name-allowlist: bullmq",
    )
    assert rubric.detect_profile_from_name("agenda", "npm") == (
        rubric.PROFILE_TASK_QUEUE, "name-allowlist: agenda",
    )


def test_npm_tensorflow_etc_detect_as_ml_framework():
    assert rubric.detect_profile_from_name("@tensorflow/tfjs", "npm") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: @tensorflow/tfjs",
    )
    assert rubric.detect_profile_from_name("@xenova/transformers", "npm") == (
        rubric.PROFILE_ML_FRAMEWORK, "name-allowlist: @xenova/transformers",
    )


def test_npm_temporalio_scoped_detects_as_workflow_orchestrator():
    assert rubric.detect_profile_from_name("@temporalio/client", "npm") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: @temporalio/client",
    )
    assert rubric.detect_profile_from_name("@temporalio/worker", "npm") == (
        rubric.PROFILE_WORKFLOW_ORCHESTRATOR, "name-allowlist: @temporalio/worker",
    )


def test_npm_typedoc_docusaurus_etc_detect_as_doc_builder():
    assert rubric.detect_profile_from_name("typedoc", "npm") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: typedoc",
    )
    assert rubric.detect_profile_from_name("@docusaurus/core", "npm") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: @docusaurus/core",
    )
    assert rubric.detect_profile_from_name("vitepress", "npm") == (
        rubric.PROFILE_DOC_BUILDER, "name-allowlist: vitepress",
    )


def test_npm_unknown_packages_are_not_detected():
    assert rubric.detect_profile_from_name("lodash", "npm") is None
    assert rubric.detect_profile_from_name("zod", "npm") is None
    assert rubric.detect_profile_from_name("@modelcontextprotocol/sdk", "npm") is None


def test_normal_libraries_are_not_detected():
    assert rubric.detect_profile_from_name("lodash", "npm") is None
    # `mcp` pypi: now classified as mcp-server SDK; see test_mcp_sdk_detected_as_mcp_server.
    assert rubric.detect_profile_from_name("@modelcontextprotocol/sdk", "npm") is None
    assert rubric.detect_profile_from_name("pyyaml", "pypi") is None


def test_empty_or_unknown_ecosystem_returns_none():
    assert rubric.detect_profile_from_name("", "pypi") is None
    assert rubric.detect_profile_from_name("mcp-server-foo", "unknown") is None
