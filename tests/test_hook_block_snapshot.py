"""Snapshot the user-facing hook block message.

The hook stderr output is part of the UX contract -- a refactor that
silently reorders sections or drops the actionable hint would degrade
the user's mental model. Two scenarios are pinned: a `blocked-role-typical`
classification (deductions land on role-relaxed surfaces; safe to accept
after a quick read) and a `blocked-suspicious` classification (role-atypical
deductions dominate; warrants real review).

These tests bypass the audit pipeline by injecting a synthetic TreeNode
into `deps.audit_tree`. The block message is the same regardless of how
the verdict was produced, so the snapshot captures the rendering layer
in isolation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localguard import deps as deps_mod
from localguard import hook
from localguard.preflight import Verdict


SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def _normalize(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").splitlines())


def _make_blocked_node(name: str, version: str, library_status: str, share: float, score: int) -> deps_mod.TreeNode:
    verdict = Verdict(
        status="low-score",
        spec_name=name,
        spec_version=version,
        ecosystem="pypi",
        score=score,
        reasons=[
            "no prior baseline in library",
            f"score {score} below threshold 50",
            f"library-status: {library_status} (role_typical_share={share:.2f})",
        ],
        library_status=library_status,
        role_typical_share=share,
    )
    return deps_mod.TreeNode(name=name, version=version, ecosystem="pypi", verdict=verdict)


@pytest.fixture
def _inject(monkeypatch):
    """Substitute audit_tree with a function returning the prepared node."""
    def _install(node: deps_mod.TreeNode):
        monkeypatch.setattr(deps_mod, "audit_tree", lambda *args, **kwargs: node)
        monkeypatch.setattr(hook.deps_mod, "audit_tree", lambda *args, **kwargs: node)
    return _install


def _payload(spec: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": f"pip install {spec}"}})


def test_hook_block_message_role_typical_snapshot(_inject):
    node = _make_blocked_node("rt-pkg", "1.0.0", library_status="blocked-role-typical", share=0.95, score=42)
    _inject(node)
    rc, out, err = hook.render_to_string(_payload("rt-pkg==1.0.0"))
    assert rc == 2
    snapshot = (SNAPSHOT_DIR / "hook_block_role_typical.txt").read_text(encoding="utf-8")
    assert _normalize(err) == _normalize(snapshot), f"\nGOT:\n{err}\nEXPECTED:\n{snapshot}"


def test_hook_block_message_suspicious_snapshot(_inject):
    node = _make_blocked_node("susp-pkg", "0.5.0", library_status="blocked-suspicious", share=0.15, score=18)
    _inject(node)
    rc, out, err = hook.render_to_string(_payload("susp-pkg==0.5.0"))
    assert rc == 2
    snapshot = (SNAPSHOT_DIR / "hook_block_suspicious.txt").read_text(encoding="utf-8")
    assert _normalize(err) == _normalize(snapshot), f"\nGOT:\n{err}\nEXPECTED:\n{snapshot}"
