from pathlib import Path

from localguard import rubric
from localguard.report import Finding, SurfaceKind


def _obf(n: int, shape: str = "dynamic") -> list[Finding]:
    """Build n obfuscation findings of the given shape (`dynamic` or `encoded`)."""
    return [
        Finding(kind=SurfaceKind.OBFUSCATION, file="pkg/runtime.py", line=i + 1, detail="eval(...)", confidence="literal", extra={"builtin": "eval", "shape": shape})
        for i in range(n)
    ]


def test_obfuscation_one_dynamic_finding_barely_dings():
    breakdown = rubric.score(_obf(1, "dynamic"))
    # dynamic per_finding under plugin = round(8 * 0.4) = 3
    assert breakdown.final_score == 97


def test_obfuscation_many_dynamic_findings_cap_at_lower_threshold():
    # Plain dynamic compile/exec (legitimate code-gen) caps at the dynamic
    # cap = round(60 * 0.4) = 24, never reaching the full 60.
    breakdown = rubric.score(_obf(20, "dynamic"))
    assert breakdown.final_score == 100 - 24


def test_obfuscation_one_encoded_finding_lands_full_weight():
    breakdown = rubric.score(_obf(1, "encoded"))
    assert breakdown.final_score == 100 - 8  # full plugin per_finding


def test_obfuscation_many_encoded_findings_hit_full_cap():
    breakdown = rubric.score(_obf(20, "encoded"))
    assert breakdown.final_score == 100 - 60  # full plugin cap


def test_obfuscation_mixed_encoded_and_dynamic_cant_exceed_total_cap():
    findings = _obf(10, "encoded") + _obf(20, "dynamic")
    breakdown = rubric.score(findings)
    # encoded: min(8*10, 60) = 60; dynamic: min(3*20, 24) = 24; total min(60+24, 60) = 60
    assert breakdown.final_score == 100 - 60


def _surf(kind: SurfaceKind, n: int) -> list[Finding]:
    return [Finding(kind=kind, file="pkg/runtime.py", line=i + 1, detail="", confidence="literal", extra={}) for i in range(n)]


def test_mcp_server_profile_relaxes_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score < server.final_score
    assert server.final_score == 100  # listening_port is zero-weight under mcp-server


def test_mcp_server_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score == 100 - 40  # cap
    assert server.final_score == 100 - 20  # mcp-server cap (5*4=20, under cap 20)


def test_mcp_server_profile_stays_strict_on_obfuscation():
    findings = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score == server.final_score


def test_cli_framework_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    cli_fw = rubric.score(findings, profile=rubric.PROFILE_CLI_FRAMEWORK)
    assert plugin.final_score == 100 - 40  # cap at 40
    assert cli_fw.final_score == 100 - 10  # cap at 10 under cli-framework (5*2=10)


def test_cli_framework_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    cli_fw = rubric.score(findings, profile=rubric.PROFILE_CLI_FRAMEWORK)
    assert plugin.final_score == cli_fw.final_score


def test_network_library_profile_relaxes_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == 100 - 25  # cap 25
    assert netlib.final_score == 100 - 5   # cap 5 under network-library


def test_network_library_profile_stays_strict_on_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == netlib.final_score


def test_network_library_profile_stays_strict_on_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 3)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == netlib.final_score


def test_web_server_profile_relaxes_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert plugin.final_score < web.final_score
    assert web.final_score == 100  # zero-weight under web-server


def test_web_server_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert plugin.final_score == web.final_score


def test_web_server_profile_relaxes_fs_write():
    findings = _surf(SurfaceKind.FS_WRITE, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert web.final_score > plugin.final_score


def test_build_tool_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert plugin.final_score == 100 - 40  # cap 40
    assert bt.final_score == 100 - 20      # cap 20 under build-tool


def test_build_tool_profile_relaxes_fs_write():
    findings = _surf(SurfaceKind.FS_WRITE, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert bt.final_score > plugin.final_score


def test_build_tool_profile_stays_strict_on_obfuscation():
    findings = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert plugin.final_score == bt.final_score


def test_data_science_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ds = rubric.score(findings, profile=rubric.PROFILE_DATA_SCIENCE)
    assert plugin.final_score == 100 - 40
    assert ds.final_score == 100 - 20


def test_data_science_profile_relaxes_fs_write():
    findings = _surf(SurfaceKind.FS_WRITE, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ds = rubric.score(findings, profile=rubric.PROFILE_DATA_SCIENCE)
    assert ds.final_score > plugin.final_score


def test_data_science_profile_stays_strict_on_outbound_and_obfuscation():
    out = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    obf = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin_out = rubric.score(out, profile=rubric.PROFILE_PLUGIN)
    ds_out = rubric.score(out, profile=rubric.PROFILE_DATA_SCIENCE)
    plugin_obf = rubric.score(obf, profile=rubric.PROFILE_PLUGIN)
    ds_obf = rubric.score(obf, profile=rubric.PROFILE_DATA_SCIENCE)
    assert plugin_out.final_score == ds_out.final_score
    assert plugin_obf.final_score == ds_obf.final_score


def test_ml_framework_profile_relaxes_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ml = rubric.score(findings, profile=rubric.PROFILE_ML_FRAMEWORK)
    assert ml.final_score > plugin.final_score


def test_ml_framework_profile_relaxes_outbound_more_than_data_science():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    ds = rubric.score(findings, profile=rubric.PROFILE_DATA_SCIENCE)
    ml = rubric.score(findings, profile=rubric.PROFILE_ML_FRAMEWORK)
    assert ml.final_score > ds.final_score


def test_ml_framework_profile_stays_strict_on_obfuscation():
    findings = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ml = rubric.score(findings, profile=rubric.PROFILE_ML_FRAMEWORK)
    assert plugin.final_score == ml.final_score


def test_database_driver_profile_relaxes_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    db = rubric.score(findings, profile=rubric.PROFILE_DATABASE_DRIVER)
    assert plugin.final_score == 100 - 25
    assert db.final_score == 100 - 10  # cap 10


def test_database_driver_profile_stays_strict_on_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 3)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    db = rubric.score(findings, profile=rubric.PROFILE_DATABASE_DRIVER)
    assert plugin.final_score == db.final_score


def test_database_driver_profile_stays_strict_on_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    db = rubric.score(findings, profile=rubric.PROFILE_DATABASE_DRIVER)
    assert plugin.final_score == db.final_score


def test_template_engine_profile_lowers_obfuscation_cap():
    # Use encoded findings to hit the full cap (dynamic findings cap at
    # the lower dynamic-ratio, which is the same shape as the cap is
    # what we're testing here).
    findings = _obf(20, "encoded")
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    tpl = rubric.score(findings, profile=rubric.PROFILE_TEMPLATE_ENGINE)
    assert plugin.final_score == 100 - 60  # plugin cap
    assert tpl.final_score == 100 - 30     # template-engine cap


def test_template_engine_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    tpl = rubric.score(findings, profile=rubric.PROFILE_TEMPLATE_ENGINE)
    assert plugin.final_score == tpl.final_score


def test_test_framework_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    tf = rubric.score(findings, profile=rubric.PROFILE_TEST_FRAMEWORK)
    assert plugin.final_score == 100 - 40
    assert tf.final_score == 100 - 20


def test_test_framework_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    tf = rubric.score(findings, profile=rubric.PROFILE_TEST_FRAMEWORK)
    assert plugin.final_score == tf.final_score


def test_cloud_sdk_profile_relaxes_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    csk = rubric.score(findings, profile=rubric.PROFILE_CLOUD_SDK)
    assert plugin.final_score == 100 - 25
    assert csk.final_score == 100 - 10


def test_cloud_sdk_profile_stays_strict_on_env_secret_and_subprocess():
    env_findings = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    sp_findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin_env = rubric.score(env_findings, profile=rubric.PROFILE_PLUGIN)
    csk_env = rubric.score(env_findings, profile=rubric.PROFILE_CLOUD_SDK)
    plugin_sp = rubric.score(sp_findings, profile=rubric.PROFILE_PLUGIN)
    csk_sp = rubric.score(sp_findings, profile=rubric.PROFILE_CLOUD_SDK)
    assert plugin_env.final_score == csk_env.final_score
    assert plugin_sp.final_score == csk_sp.final_score


def test_observability_profile_relaxes_telemetry_endpoint():
    findings = _surf(SurfaceKind.TELEMETRY_ENDPOINT, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    obs = rubric.score(findings, profile=rubric.PROFILE_OBSERVABILITY)
    assert plugin.final_score == 100 - 20  # plugin cap
    assert obs.final_score == 100 - 10     # observability cap


def test_observability_profile_stays_strict_on_subprocess_and_env_secret():
    sp = _surf(SurfaceKind.SUBPROCESS, 4)
    env = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    plugin_sp = rubric.score(sp, profile=rubric.PROFILE_PLUGIN)
    obs_sp = rubric.score(sp, profile=rubric.PROFILE_OBSERVABILITY)
    plugin_env = rubric.score(env, profile=rubric.PROFILE_PLUGIN)
    obs_env = rubric.score(env, profile=rubric.PROFILE_OBSERVABILITY)
    assert plugin_sp.final_score == obs_sp.final_score
    assert plugin_env.final_score == obs_env.final_score


def test_format_codec_profile_relaxes_subprocess_and_fs_write():
    sp = _surf(SurfaceKind.SUBPROCESS, 5)
    fw = _surf(SurfaceKind.FS_WRITE, 5)
    plugin_sp = rubric.score(sp, profile=rubric.PROFILE_PLUGIN)
    fc_sp = rubric.score(sp, profile=rubric.PROFILE_FORMAT_CODEC)
    plugin_fw = rubric.score(fw, profile=rubric.PROFILE_PLUGIN)
    fc_fw = rubric.score(fw, profile=rubric.PROFILE_FORMAT_CODEC)
    assert fc_sp.final_score > plugin_sp.final_score
    assert fc_fw.final_score > plugin_fw.final_score


def test_format_codec_profile_stays_strict_on_outbound_xxe_surface():
    # XML / HTML parsers fetching external entities is THE XXE attack
    # surface; format-codec must NOT relax outbound_network or
    # outbound_dynamic.
    on = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    od = _surf(SurfaceKind.OUTBOUND_DYNAMIC, 5)
    plugin_on = rubric.score(on, profile=rubric.PROFILE_PLUGIN)
    fc_on = rubric.score(on, profile=rubric.PROFILE_FORMAT_CODEC)
    plugin_od = rubric.score(od, profile=rubric.PROFILE_PLUGIN)
    fc_od = rubric.score(od, profile=rubric.PROFILE_FORMAT_CODEC)
    assert plugin_on.final_score == fc_on.final_score
    assert plugin_od.final_score == fc_od.final_score


def test_scraping_profile_relaxes_outbound_dynamic_and_listening_port():
    findings = _surf(SurfaceKind.OUTBOUND_DYNAMIC, 10) + _surf(SurfaceKind.LISTENING_PORT, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    sc = rubric.score(findings, profile=rubric.PROFILE_SCRAPING)
    assert sc.final_score > plugin.final_score


def test_scraping_profile_stays_strict_on_env_secret_and_data_exfil():
    env = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    exfil = _surf(SurfaceKind.DATA_EXFIL_HINT, 2)
    plugin_env = rubric.score(env, profile=rubric.PROFILE_PLUGIN)
    sc_env = rubric.score(env, profile=rubric.PROFILE_SCRAPING)
    plugin_exfil = rubric.score(exfil, profile=rubric.PROFILE_PLUGIN)
    sc_exfil = rubric.score(exfil, profile=rubric.PROFILE_SCRAPING)
    assert plugin_env.final_score == sc_env.final_score
    assert plugin_exfil.final_score == sc_exfil.final_score


def test_role_typicality_marks_relaxed_surfaces():
    # Under network-library, outbound_network is relaxed (cap 5 vs plugin 25);
    # subprocess is NOT relaxed.
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 3) + _surf(SurfaceKind.SUBPROCESS, 2)
    breakdown = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    by_kind = {d["kind"]: d for d in breakdown.deductions}
    assert by_kind["outbound_network"]["role_typical"] is True
    assert by_kind["subprocess"]["role_typical"] is False


def test_role_typical_share_high_when_only_relaxed_surfaces_fire():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    breakdown = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert breakdown.role_typical_share == 1.0


def test_role_typical_share_zero_under_plugin_profile():
    # Plugin is the baseline; no surface is "relaxed vs plugin" by definition.
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    breakdown = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    assert breakdown.role_typical_share == 0.0
    assert all(d["role_typical"] is False for d in breakdown.deductions)


def test_role_typical_share_split_when_mixed_surfaces_fire():
    # Under cloud-sdk: outbound_network is relaxed (cap 10 vs 25), env_secret_read
    # stays strict (10/20 unchanged). Mix some of each.
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10) + _surf(SurfaceKind.ENV_SECRET_READ, 2)
    breakdown = rubric.score(findings, profile=rubric.PROFILE_CLOUD_SDK)
    # outbound: cap 10 = 10 pts; env_secret_read: 2 * 10 = 20 pts; total 30
    # role_typical (outbound): 10/30 = 0.333
    assert breakdown.role_typical_share == round(10 / 30, 3)


def test_web_framework_profile_relaxes_subprocess_and_fs_write():
    sp = _surf(SurfaceKind.SUBPROCESS, 5)
    fw = _surf(SurfaceKind.FS_WRITE, 8)
    plugin_sp = rubric.score(sp, profile=rubric.PROFILE_PLUGIN)
    wf_sp = rubric.score(sp, profile=rubric.PROFILE_WEB_FRAMEWORK)
    plugin_fw = rubric.score(fw, profile=rubric.PROFILE_PLUGIN)
    wf_fw = rubric.score(fw, profile=rubric.PROFILE_WEB_FRAMEWORK)
    assert wf_sp.final_score > plugin_sp.final_score
    assert wf_fw.final_score > plugin_fw.final_score


def test_web_framework_profile_stays_strict_on_env_secret_and_obfuscation():
    env = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    plugin_env = rubric.score(env, profile=rubric.PROFILE_PLUGIN)
    wf_env = rubric.score(env, profile=rubric.PROFILE_WEB_FRAMEWORK)
    assert plugin_env.final_score == wf_env.final_score


def test_async_runtime_profile_relaxes_listening_port_and_subprocess():
    findings = _surf(SurfaceKind.LISTENING_PORT, 3) + _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ar = rubric.score(findings, profile=rubric.PROFILE_ASYNC_RUNTIME)
    assert ar.final_score > plugin.final_score


def test_async_runtime_profile_stays_strict_on_env_secret_and_obfuscation():
    findings = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    ar = rubric.score(findings, profile=rubric.PROFILE_ASYNC_RUNTIME)
    assert plugin.final_score == ar.final_score


def test_task_queue_profile_relaxes_subprocess_and_outbound():
    sp = _surf(SurfaceKind.SUBPROCESS, 5)
    on = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    plugin_sp = rubric.score(sp, profile=rubric.PROFILE_PLUGIN)
    tq_sp = rubric.score(sp, profile=rubric.PROFILE_TASK_QUEUE)
    plugin_on = rubric.score(on, profile=rubric.PROFILE_PLUGIN)
    tq_on = rubric.score(on, profile=rubric.PROFILE_TASK_QUEUE)
    assert tq_sp.final_score > plugin_sp.final_score
    assert tq_on.final_score > plugin_on.final_score


def test_notebook_runtime_profile_lowers_obfuscation_cap():
    findings = _obf(20, "encoded")
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    nb = rubric.score(findings, profile=rubric.PROFILE_NOTEBOOK_RUNTIME)
    assert plugin.final_score == 100 - 60  # plugin cap
    assert nb.final_score == 100 - 30      # notebook-runtime cap


def test_notebook_runtime_profile_relaxes_subprocess_and_fs_write():
    sp = _surf(SurfaceKind.SUBPROCESS, 5)
    fw = _surf(SurfaceKind.FS_WRITE, 6)
    plugin_sp = rubric.score(sp, profile=rubric.PROFILE_PLUGIN)
    nb_sp = rubric.score(sp, profile=rubric.PROFILE_NOTEBOOK_RUNTIME)
    plugin_fw = rubric.score(fw, profile=rubric.PROFILE_PLUGIN)
    nb_fw = rubric.score(fw, profile=rubric.PROFILE_NOTEBOOK_RUNTIME)
    assert nb_sp.final_score > plugin_sp.final_score
    assert nb_fw.final_score > plugin_fw.final_score


def test_notebook_runtime_profile_stays_strict_on_env_secret_and_data_exfil():
    env = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    exfil = _surf(SurfaceKind.DATA_EXFIL_HINT, 2)
    plugin_env = rubric.score(env, profile=rubric.PROFILE_PLUGIN)
    nb_env = rubric.score(env, profile=rubric.PROFILE_NOTEBOOK_RUNTIME)
    plugin_exfil = rubric.score(exfil, profile=rubric.PROFILE_PLUGIN)
    nb_exfil = rubric.score(exfil, profile=rubric.PROFILE_NOTEBOOK_RUNTIME)
    assert plugin_env.final_score == nb_env.final_score
    assert plugin_exfil.final_score == nb_exfil.final_score


def test_data_app_profile_relaxes_listening_port_and_subprocess_and_fs_write():
    findings = (
        _surf(SurfaceKind.LISTENING_PORT, 3)
        + _surf(SurfaceKind.SUBPROCESS, 5)
        + _surf(SurfaceKind.FS_WRITE, 8)
    )
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    da = rubric.score(findings, profile=rubric.PROFILE_DATA_APP)
    assert da.final_score > plugin.final_score


def test_data_app_profile_stays_strict_on_env_secret_data_exfil_and_telemetry():
    env = _surf(SurfaceKind.ENV_SECRET_READ, 3)
    exfil = _surf(SurfaceKind.DATA_EXFIL_HINT, 2)
    tel = _surf(SurfaceKind.TELEMETRY_ENDPOINT, 3)
    plugin_env = rubric.score(env, profile=rubric.PROFILE_PLUGIN)
    da_env = rubric.score(env, profile=rubric.PROFILE_DATA_APP)
    plugin_exfil = rubric.score(exfil, profile=rubric.PROFILE_PLUGIN)
    da_exfil = rubric.score(exfil, profile=rubric.PROFILE_DATA_APP)
    plugin_tel = rubric.score(tel, profile=rubric.PROFILE_PLUGIN)
    da_tel = rubric.score(tel, profile=rubric.PROFILE_DATA_APP)
    assert plugin_env.final_score == da_env.final_score
    assert plugin_exfil.final_score == da_exfil.final_score
    assert plugin_tel.final_score == da_tel.final_score


def test_unknown_profile_falls_back_to_plugin_weights():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    bogus = rubric.score(findings, profile="not-a-real-profile")
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    assert bogus.final_score == plugin.final_score
