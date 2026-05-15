"""Pure-function invariants that must hold across every profile.

These are properties — propositions that should be true for *every* profile
and *every* synthetic finding mix. Cheap to enumerate; they catch the kind
of weight-table edit that silently breaks an axiom (a cap that goes
negative, share that goes >1.0, deduction exceeding cap, plugin somehow
flagging a finding as role-typical).
"""
from __future__ import annotations

import pytest

from localguard import rubric
from localguard.report import Finding, SurfaceKind
from localguard.rubric import PLUGIN_WEIGHTS, PROFILE_WEIGHTS, STARTING_SCORE, score


ALL_PROFILES: list[str] = sorted(PROFILE_WEIGHTS.keys())


def _finding(kind: SurfaceKind, line: int, *, shape: str | None = None) -> Finding:
    extra: dict = {}
    if kind == SurfaceKind.OUTBOUND_NETWORK or kind == SurfaceKind.HARDCODED_HOST or kind == SurfaceKind.TELEMETRY_ENDPOINT:
        extra["host"] = f"host-{line}.example.com"
    if kind == SurfaceKind.OBFUSCATION:
        extra["shape"] = shape or "dynamic"
    if kind == SurfaceKind.ENV_SECRET_READ:
        extra["env_name"] = f"SECRET_{line}"
    return Finding(kind=kind, file="pkg/runtime.py", line=line, detail=f"{kind.value} detail", extra=extra)


# Synthetic finding mixes. Each is a small handful of findings designed to
# touch several surface families at once.
MIXES: dict[str, list[Finding]] = {
    "empty": [],
    "single_net": [_finding(SurfaceKind.OUTBOUND_NETWORK, 1)],
    "wide_strict": [
        _finding(SurfaceKind.OUTBOUND_NETWORK, 1),
        _finding(SurfaceKind.LISTENING_PORT, 2),
        _finding(SurfaceKind.SUBPROCESS, 3),
        _finding(SurfaceKind.ENV_SECRET_READ, 4),
        _finding(SurfaceKind.OBFUSCATION, 5, shape="dynamic"),
        _finding(SurfaceKind.OBFUSCATION, 6, shape="encoded"),
        _finding(SurfaceKind.DATA_EXFIL_HINT, 7),
    ],
    "all_relaxable": [
        _finding(SurfaceKind.OUTBOUND_NETWORK, 1),
        _finding(SurfaceKind.OUTBOUND_NETWORK, 2),
        _finding(SurfaceKind.SUBPROCESS, 3),
        _finding(SurfaceKind.FS_WRITE, 4),
    ],
    "mcp_shaped": [
        _finding(SurfaceKind.MCP_TOOL, 1),
        _finding(SurfaceKind.MCP_RESOURCE, 2),
        _finding(SurfaceKind.OUTBOUND_NETWORK, 3),
    ],
    "many_obfuscation": [_finding(SurfaceKind.OBFUSCATION, i, shape="dynamic") for i in range(8)],
}


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize("mix_name", list(MIXES.keys()))
def test_score_is_bounded(profile: str, mix_name: str):
    s = score(MIXES[mix_name], profile=profile)
    assert 0 <= s.final_score <= STARTING_SCORE, f"profile={profile} mix={mix_name} score={s.final_score}"


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize("mix_name", list(MIXES.keys()))
def test_role_typical_share_is_bounded(profile: str, mix_name: str):
    s = score(MIXES[mix_name], profile=profile)
    assert 0.0 <= s.role_typical_share <= 1.0, f"profile={profile} mix={mix_name} share={s.role_typical_share}"


@pytest.mark.parametrize("mix_name", list(MIXES.keys()))
def test_plugin_share_is_always_zero(mix_name: str):
    """The plugin profile relaxes nothing vs. itself, so role-typicality is
    zero for every finding mix."""
    s = score(MIXES[mix_name], profile="plugin")
    assert s.role_typical_share == 0.0, f"plugin mix={mix_name} share={s.role_typical_share}"


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize("mix_name", list(MIXES.keys()))
def test_per_deduction_within_cap(profile: str, mix_name: str):
    """Each deduction's `deducted` must respect the surface's cap."""
    s = score(MIXES[mix_name], profile=profile)
    for d in s.deductions:
        assert d["deducted"] <= d["cap"], f"profile={profile} mix={mix_name} surface={d.get('kind')} deducted={d['deducted']} cap={d['cap']}"
        assert d["deducted"] >= 0


@pytest.mark.parametrize("profile", ALL_PROFILES)
@pytest.mark.parametrize("mix_name", list(MIXES.keys()))
def test_total_deducted_matches_score(profile: str, mix_name: str):
    """`final_score == max(0, STARTING_SCORE - sum(deducted))`."""
    s = score(MIXES[mix_name], profile=profile)
    total = sum(d["deducted"] for d in s.deductions)
    assert s.final_score == max(0, STARTING_SCORE - total)


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_obfuscation_split_count_consistency(profile: str):
    """For the obfuscation surface, the deduction's `count` field equals
    encoded + dynamic. We exercise this by feeding 5 encoded + 3 dynamic."""
    mix = [_finding(SurfaceKind.OBFUSCATION, i, shape="encoded") for i in range(5)]
    mix += [_finding(SurfaceKind.OBFUSCATION, i + 100, shape="dynamic") for i in range(3)]
    s = score(mix, profile=profile)
    obf = [d for d in s.deductions if d.get("kind") == SurfaceKind.OBFUSCATION.value]
    if not obf:
        # Profile has cap=0 on obfuscation; deduction is filtered out at build time.
        return
    assert obf[0]["count"] == 8


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_relaxed_surface_marked_role_typical(profile: str):
    """If the profile relaxes any surface vs. plugin (per_finding strictly
    lower or cap strictly lower), and a finding lands on that surface, the
    resulting deduction must be marked `role_typical=True`."""
    if profile == "plugin":
        return  # plugin relaxes nothing vs. itself
    weights = PROFILE_WEIGHTS[profile]
    relaxed: list[SurfaceKind] = []
    for kind, w in weights.items():
        plugin_w = PLUGIN_WEIGHTS.get(kind)
        if plugin_w is None:
            continue
        if w.per_finding < plugin_w.per_finding or w.cap < plugin_w.cap:
            relaxed.append(kind)
    # Pick the first relaxed non-obfuscation surface for a clean test.
    test_kind = next((k for k in relaxed if k != SurfaceKind.OBFUSCATION), None)
    if test_kind is None:
        return  # nothing relaxable to test (e.g., profile only relaxes obfuscation)
    mix = [_finding(test_kind, 1)]
    s = score(mix, profile=profile)
    matching = [d for d in s.deductions if d.get("kind") == test_kind.value]
    if not matching:
        return  # cap=0 (surface entirely disabled — also a form of relaxation, but no deduction emitted)
    assert matching[0].get("role_typical") is True, f"profile={profile} surface={test_kind.value} should be role-typical"
