"""Hygiene invariants for the role-profile name allowlists.

These checks catch the easy-to-make mistakes when growing the allowlists:
typos in canonical form, the same name landing in two profiles (which would
make classification depend on detection order), and prefix/name overlaps on
the npm side (a name covered by a prefix should not also need to be listed
explicitly). They also assert that every listed name actually round-trips
through `detect_profile_from_name` to the profile it was filed under -- if
someone reorders the if-chain or drops a branch, this catches it.
"""
from __future__ import annotations

import re

import pytest

from localguard import rubric as R


PYPI_SETS: dict[str, set[str]] = {
    R.PROFILE_CLI_FRAMEWORK: R.CLI_FRAMEWORK_NAMES,
    R.PROFILE_NETWORK_LIBRARY: R.NETWORK_LIBRARY_NAMES,
    R.PROFILE_WEB_SERVER: R.WEB_SERVER_NAMES,
    R.PROFILE_BUILD_TOOL: R.BUILD_TOOL_NAMES,
    R.PROFILE_DATA_SCIENCE: R.DATA_SCIENCE_NAMES,
    R.PROFILE_ML_FRAMEWORK: R.ML_FRAMEWORK_NAMES,
    R.PROFILE_DATABASE_DRIVER: R.DATABASE_DRIVER_NAMES,
    R.PROFILE_TEMPLATE_ENGINE: R.TEMPLATE_ENGINE_NAMES,
    R.PROFILE_TEST_FRAMEWORK: R.TEST_FRAMEWORK_NAMES,
    R.PROFILE_CLOUD_SDK: R.CLOUD_SDK_NAMES,
    R.PROFILE_OBSERVABILITY: R.OBSERVABILITY_NAMES,
    R.PROFILE_FORMAT_CODEC: R.FORMAT_CODEC_NAMES,
    R.PROFILE_SCRAPING: R.SCRAPING_NAMES,
    R.PROFILE_WEB_FRAMEWORK: R.WEB_FRAMEWORK_NAMES,
    R.PROFILE_ASYNC_RUNTIME: R.ASYNC_RUNTIME_NAMES,
    R.PROFILE_TASK_QUEUE: R.TASK_QUEUE_NAMES,
    R.PROFILE_NOTEBOOK_RUNTIME: R.NOTEBOOK_RUNTIME_NAMES,
    R.PROFILE_DATA_APP: R.DATA_APP_NAMES,
    R.PROFILE_WORKFLOW_ORCHESTRATOR: R.WORKFLOW_ORCHESTRATOR_NAMES,
    R.PROFILE_DOC_BUILDER: R.DOC_BUILDER_NAMES,
    R.PROFILE_AGENTIC_FRAMEWORK: R.AGENTIC_FRAMEWORK_NAMES,
    R.PROFILE_GUI_TOOLKIT: R.GUI_TOOLKIT_NAMES,
}

NPM_SETS: dict[str, set[str]] = {
    R.PROFILE_CLI_FRAMEWORK: R.CLI_FRAMEWORK_NPM_NAMES,
    R.PROFILE_NETWORK_LIBRARY: R.NETWORK_LIBRARY_NPM_NAMES,
    R.PROFILE_BUILD_TOOL: R.BUILD_TOOL_NPM_NAMES,
    R.PROFILE_ML_FRAMEWORK: R.ML_FRAMEWORK_NPM_NAMES,
    R.PROFILE_DATABASE_DRIVER: R.DATABASE_DRIVER_NPM_NAMES,
    R.PROFILE_TEMPLATE_ENGINE: R.TEMPLATE_ENGINE_NPM_NAMES,
    R.PROFILE_TEST_FRAMEWORK: R.TEST_FRAMEWORK_NPM_NAMES,
    R.PROFILE_CLOUD_SDK: R.CLOUD_SDK_NPM_NAMES,
    R.PROFILE_OBSERVABILITY: R.OBSERVABILITY_NPM_NAMES,
    R.PROFILE_FORMAT_CODEC: R.FORMAT_CODEC_NPM_NAMES,
    R.PROFILE_SCRAPING: R.SCRAPING_NPM_NAMES,
    R.PROFILE_WEB_FRAMEWORK: R.WEB_FRAMEWORK_NPM_NAMES,
    R.PROFILE_TASK_QUEUE: R.TASK_QUEUE_NPM_NAMES,
    R.PROFILE_WORKFLOW_ORCHESTRATOR: R.WORKFLOW_ORCHESTRATOR_NPM_NAMES,
    R.PROFILE_DOC_BUILDER: R.DOC_BUILDER_NPM_NAMES,
    R.PROFILE_AGENTIC_FRAMEWORK: R.AGENTIC_FRAMEWORK_NPM_NAMES,
}

NPM_PREFIXES: dict[str, tuple[str, ...]] = {
    R.PROFILE_CLOUD_SDK: R.CLOUD_SDK_NPM_PREFIXES,
    R.PROFILE_OBSERVABILITY: R.OBSERVABILITY_NPM_PREFIXES,
    R.PROFILE_WEB_FRAMEWORK: R.WEB_FRAMEWORK_NPM_PREFIXES,
    R.PROFILE_WORKFLOW_ORCHESTRATOR: R.WORKFLOW_ORCHESTRATOR_NPM_PREFIXES,
    R.PROFILE_DOC_BUILDER: R.DOC_BUILDER_NPM_PREFIXES,
    R.PROFILE_AGENTIC_FRAMEWORK: R.AGENTIC_FRAMEWORK_NPM_PREFIXES,
}


# PEP 503 canonical: lowercase, runs of [-_.] collapsed to a single `-`.
_PEP503_OK = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def test_pypi_names_are_pep503_canonical():
    bad: list[tuple[str, str]] = []
    for profile, names in PYPI_SETS.items():
        for name in names:
            if not _PEP503_OK.fullmatch(name):
                bad.append((profile, name))
    assert not bad, f"non-canonical pypi names: {bad}"


def test_no_pypi_name_in_two_profiles():
    seen: dict[str, str] = {}
    dupes: list[tuple[str, str, str]] = []
    for profile, names in PYPI_SETS.items():
        for name in names:
            if name in seen and seen[name] != profile:
                dupes.append((name, seen[name], profile))
            else:
                seen[name] = profile
    assert not dupes, f"pypi names in multiple profiles: {dupes}"


def test_no_npm_name_in_two_profiles():
    seen: dict[str, str] = {}
    dupes: list[tuple[str, str, str]] = []
    for profile, names in NPM_SETS.items():
        for name in names:
            if name in seen and seen[name] != profile:
                dupes.append((name, seen[name], profile))
            else:
                seen[name] = profile
    assert not dupes, f"npm names in multiple profiles: {dupes}"


def test_no_npm_name_redundant_with_its_own_profile_prefix():
    """A name listed explicitly should not also be covered by a prefix of the
    same profile -- that would be dead-weight in the names set."""
    redundant: list[tuple[str, str, str]] = []
    for profile, names in NPM_SETS.items():
        prefixes = NPM_PREFIXES.get(profile, ())
        for name in names:
            for p in prefixes:
                if name.startswith(p):
                    redundant.append((profile, name, p))
    assert not redundant, f"npm names redundant with own profile prefix: {redundant}"


def test_no_npm_name_overlaps_other_profile_prefix():
    """A name should not be covered by a *different* profile's prefix -- the
    name-allowlist branch fires first in `detect_profile_from_name`, but the
    overlap means ambiguous semantics; flag it loudly."""
    conflicts: list[tuple[str, str, str, str]] = []
    for profile, names in NPM_SETS.items():
        for other_profile, prefixes in NPM_PREFIXES.items():
            if other_profile == profile:
                continue
            for name in names:
                for p in prefixes:
                    if name.startswith(p):
                        conflicts.append((name, profile, other_profile, p))
    assert not conflicts, f"npm name overlaps another profile's prefix: {conflicts}"


@pytest.mark.parametrize(
    "ecosystem,pairs",
    [
        ("pypi", [(p, n) for p, names in PYPI_SETS.items() for n in names]),
        ("npm", [(p, n) for p, names in NPM_SETS.items() for n in names]),
    ],
    ids=["pypi", "npm"],
)
def test_every_listed_name_round_trips(ecosystem: str, pairs: list[tuple[str, str]]):
    """Every name in every allowlist must resolve back to the profile it was
    filed under. Catches: dropped branches in `detect_profile_from_name`,
    re-ordering issues where an earlier set already swallowed the name."""
    mismatches: list[tuple[str, str, str, str | None]] = []
    for expected_profile, name in pairs:
        result = R.detect_profile_from_name(name, ecosystem)
        got = result[0] if result else None
        if got != expected_profile:
            mismatches.append((ecosystem, name, expected_profile, got))
    assert not mismatches, f"name->profile round-trip mismatches: {mismatches}"
