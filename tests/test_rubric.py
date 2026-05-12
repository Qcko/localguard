from pathlib import Path

from localguard import rubric
from localguard.report import Finding, SurfaceKind


def _obf(n: int) -> list[Finding]:
    return [
        Finding(kind=SurfaceKind.OBFUSCATION, file="pkg/runtime.py", line=i + 1, detail="eval(...)", confidence="literal", extra={})
        for i in range(n)
    ]


def test_obfuscation_one_finding_stays_auto_baselineable():
    breakdown = rubric.score(_obf(1))
    assert breakdown.final_score == 92


def test_obfuscation_two_findings_drop_below_auto_threshold():
    breakdown = rubric.score(_obf(2))
    assert 80 <= breakdown.final_score < 90


def test_obfuscation_five_findings_still_acceptable_band():
    breakdown = rubric.score(_obf(5))
    assert 50 <= breakdown.final_score < 90


def test_obfuscation_many_findings_hit_low_score():
    breakdown = rubric.score(_obf(20))
    assert breakdown.final_score < 50
