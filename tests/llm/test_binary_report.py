"""Unit tests for the structured ``BinaryReport`` Pydantic model and
its outer-model serializer.

These tests exercise every validator in ``dspy_modules.BinaryReport`` /
``BehaviorSection`` / ``ObservedArtifact`` and verify that
``ClusterAnalysisResponse.model_dump()`` flattens ``binary_report`` to a
markdown string for downstream consumers.

The model has two interacting length constraints worth keeping in mind
when writing fixtures:

* ``overview`` is 200-500 chars (Pydantic ``max_length``).
* The rendered markdown total (from ``to_markdown()``) must land in
  ``[1500, 4500]`` chars (``@model_validator``).

Hitting the lower bound with the maximum ``overview`` plus a single
short ``BehaviorSection`` is impossible, so the valid-fixture builder
adds a couple of behavior sections with reasonable bodies. Tests that
intentionally violate length use bodies that are deliberately tiny or
deliberately enormous.
"""

import pytest
from pydantic import ValidationError

from xrefer.llm.dspy_modules import (
    BehaviorSection,
    BinaryCategory,
    BinaryReport,
    ClusterAnalysisItem,
    ClusterAnalysisResponse,
    IoCLabel,
    MitreAttackTechnique,
    ObservedArtifact,
    _BANNED_HEADING_RE,
)


# ── Fixture helpers ───────────────────────────────────────────────────


def _valid_overview() -> str:
    """A 300-ish char overview that satisfies the opener rule.

    Sits comfortably in [200, 500]. Plain prose, no markdown.
    """
    return (
        "The binary is a Windows credential stealer that harvests "
        "browser-stored secrets and exfiltrates them to a remote HTTP "
        "endpoint. Persistence is staged via a registry write, and the "
        "binary maintains a single-instance mutex to avoid double "
        "execution on the same host."
    )


def _valid_behavior() -> list[BehaviorSection]:
    """Four behavior sections sized to push the rendered total above
    1500 chars while keeping each section under what would feel cramped.
    """
    long_body = (
        "Walks the registry under user-profile and machine-wide hives, "
        "reading values that name the wallet, mail-client, and VPN "
        "configuration paths. Each match is staged into an in-memory "
        "structure keyed by application identifier before serialization. "
        "Errors during enumeration are caught and dropped, so partial "
        "results still produce a payload."
    )
    return [
        BehaviorSection(
            heading="System and user discovery via Windows API",
            body=(
                "Queries computer name, current user, OS version, and "
                "physical memory status. Enumerates logical drives and "
                "maps standard system folders to locate target files. "
                "Each call's return value is checked and logged into an "
                "in-memory structure that is later included in the "
                "exfiltration payload."
            ),
        ),
        BehaviorSection(
            heading="Registry queries against application data paths",
            body=long_body,
        ),
        BehaviorSection(
            heading="HTTP POSTs to a fixed endpoint via `WinHttp`",
            body=(
                "Sends collected data via POST. The user-agent string "
                "mimics a macOS Chrome browser. Connections are "
                "single-shot — no keep-alive, no retry on failure. "
                "Failures are silently swallowed so a missing C2 host "
                "does not crash the binary."
            ),
        ),
        BehaviorSection(
            heading="Single-instance enforcement via named mutex",
            body=(
                "Creates a named mutex at startup and aborts if the mutex "
                "already exists, ensuring only one instance per host. The "
                "mutex name is hardcoded in the binary's string table."
            ),
        ),
    ]


def _valid_artifacts() -> list[ObservedArtifact]:
    return [
        ObservedArtifact(label=IoCLabel.DOMAIN, value="tastedata.shop"),
        ObservedArtifact(label=IoCLabel.URL_PATH, value="/ag-ap.php"),
        ObservedArtifact(label=IoCLabel.MUTEX, value="filemanager1"),
    ]


def _valid_report(**overrides) -> BinaryReport:
    """Build a BinaryReport that passes every validator. Tests override
    fields to exercise specific failure modes.
    """
    kwargs = dict(
        overview=_valid_overview(),
        behavior=_valid_behavior(),
        observed_artifacts=_valid_artifacts(),
    )
    kwargs.update(overrides)
    return BinaryReport(**kwargs)


def _valid_cluster_item() -> ClusterAnalysisItem:
    """Minimal per-cluster entry so ClusterAnalysisResponse can be built
    end-to-end for the outer-serializer test.
    """
    return ClusterAnalysisItem(
        cluster_id="cluster_1",
        label="entry point",
        description="Initialises runtime state and dispatches behaviour clusters.",
        relationships="Calls into worker clusters that perform the actual collection work.",
        function_prefix="entry",
        library_or_runtime=0,
        mitre_attack=[
            MitreAttackTechnique(
                id="T1059.003",
                tactic="Execution",
                name="Command and Scripting Interpreter: Windows Command Shell",
                rationale=(
                    "invokes `cmd.exe` with `/c` arguments visible in cluster "
                    "strings."
                ),
            )
        ],
    )


# ── 1. Valid input ────────────────────────────────────────────────────


def test_valid_report_passes_all_validators():
    """A hand-written report that satisfies every rule should
    instantiate without raising.
    """
    r = _valid_report()
    md = r.to_markdown()
    assert md.startswith("## Overview\n")
    assert "\n## Behavior\n" in md
    assert "\n## Observed Artifacts\n" in md
    # Exactly three top-level headings, in order, no extras.
    h2 = [line for line in md.splitlines() if line.startswith("## ")]
    assert h2 == ["## Overview", "## Behavior", "## Observed Artifacts"]
    # Behavior subheadings render as `### `.
    h3 = [line for line in md.splitlines() if line.startswith("### ")]
    assert len(h3) == len(_valid_behavior())
    # Observed-artifact lines match the `- **Label**: \`value\`` shape.
    for art in _valid_artifacts():
        assert f"- **{art.label.value}**: `{art.value}`" in md
    # Total length is inside the [1500, 4500] band.
    assert 1500 <= len(md) <= 4500, len(md)


def test_empty_observed_artifacts_renders_fallback_sentence():
    """observed_artifacts defaults to ``[]``; the markdown output must
    fall back to the literal sentence instead of leaving the section
    body blank.
    """
    # Pad the bodies enough to clear the 1500-char minimum without
    # leaning on the artifacts list.
    padded = _valid_behavior() + [
        BehaviorSection(
            heading="Filesystem enumeration via `FindFirstFile`",
            body=(
                "Recursively walks user-profile directories, collecting "
                "file names and timestamps. Matches are appended to an "
                "in-memory list. Errors on individual directories are "
                "ignored — enumeration continues across the rest of the "
                "tree."
            ),
        ),
    ]
    r = _valid_report(behavior=padded, observed_artifacts=[])
    md = r.to_markdown()
    assert (
        "No observable artifacts were extracted from the analyzed data."
        in md
    )


# ── 2. Missing sections ───────────────────────────────────────────────


def test_missing_overview_raises():
    with pytest.raises(ValidationError):
        BinaryReport(
            behavior=_valid_behavior(),
            observed_artifacts=_valid_artifacts(),
        )


def test_empty_behavior_list_raises():
    with pytest.raises(ValidationError):
        BinaryReport(
            overview=_valid_overview(),
            behavior=[],
            observed_artifacts=_valid_artifacts(),
        )


def test_explicit_none_observed_artifacts_raises():
    """observed_artifacts is allowed to be missing/empty (it has a
    default), but an explicit None is wrong-typed and should raise.
    """
    with pytest.raises(ValidationError):
        BinaryReport(
            overview=_valid_overview(),
            behavior=_valid_behavior(),
            observed_artifacts=None,
        )


# ── 3. Wrong opener ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_opener",
    [
        # Each filler is sized so the overview lands inside [200, 500]
        # min/max_length — we want the opener validator to be the
        # cause of failure, not the min_length validator firing first.
        "This is a binary that "
        + "spreads through phishing-attached zip files. " * 5,
        "The sample is a Windows credential stealer that "
        + "harvests browser-stored secrets. " * 5,
        "It is a tiny dropper that "
        + "stages a second-stage payload on disk. " * 5,
    ],
)
def test_overview_opener_validator(bad_opener):
    # Sanity-check the fixture so a future tweak doesn't accidentally
    # trip the min/max_length validators instead of the opener rule.
    assert 200 <= len(bad_opener) <= 500, len(bad_opener)
    with pytest.raises(ValidationError, match="open with"):
        BinaryReport(
            overview=bad_opener,
            behavior=_valid_behavior(),
            observed_artifacts=_valid_artifacts(),
        )


# ── 4. Banned subsection heading ──────────────────────────────────────

# Every term that the spec lists as a bare TTP category; matches must
# be rejected case-insensitively.
_BANNED_HEADINGS = [
    "Persistence",
    "Defense Evasion",
    "Anti-Analysis",
    "Anti Analysis",
    "Credential Theft",
    "Credential Access",
    "C2",
    "C2 Communication",
    "Command and Control",
    "Lateral Movement",
    "Privilege Escalation",
    "Reconnaissance",
    "Discovery",
    "Exfiltration",
    "Execution",
    "Initial Access",
    "Impact",
    "Collection",
    # Case-insensitivity sanity check.
    "persistence",
    "defense evasion",
]


@pytest.mark.parametrize("heading", _BANNED_HEADINGS)
def test_banned_subsection_heading_raises(heading):
    """Each bare TTP category should be rejected by
    BehaviorSection.heading's validator.
    """
    with pytest.raises(ValidationError, match="bare TTP category"):
        BehaviorSection(heading=heading, body="not empty")
    # And the regex itself agrees.
    assert _BANNED_HEADING_RE.match(heading)


def test_acceptable_heading_with_ttp_term_inside_passes():
    """Headings that *contain* a TTP-category word as part of a
    descriptive phrase must be allowed — only the bare-noun form is
    banned.
    """
    BehaviorSection(
        heading="Registry writes to startup-related keys (persistence vector)",
        body="not empty",
    )


# ── 5. Banned tokens ──────────────────────────────────────────────────


def test_banned_marketing_adjective_in_overview_raises():
    bad_overview = (
        "The binary is a sophisticated credential stealer that "
        + "harvests browser-stored secrets and exfiltrates them. " * 3
    )
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(
            overview=bad_overview,
            behavior=_valid_behavior(),
            observed_artifacts=_valid_artifacts(),
        )


def test_banned_hedge_token_in_body_raises():
    behavior = _valid_behavior()
    behavior[0] = BehaviorSection(
        heading="System discovery via Windows API",
        body=(
            "Likely queries computer name and current user, then "
            "enumerates logical drives. The pattern is consistent with "
            "credential-stealing tooling."
        ),
    )
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(
            overview=_valid_overview(),
            behavior=behavior,
            observed_artifacts=_valid_artifacts(),
        )


def test_banned_token_in_bullet_raises():
    behavior = _valid_behavior()
    behavior[0] = BehaviorSection(
        heading="Wallet-config queries",
        body="Reads registry values under wallet subtrees.",
        bullets=["`HKCU\\Software\\Wallet` — comprehensive enumeration"],
    )
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(
            overview=_valid_overview(),
            behavior=behavior,
            observed_artifacts=_valid_artifacts(),
        )


def test_cluster_id_leak_in_artifact_value_raises():
    """The literal substring ``cluster.id.`` belongs in per-cluster
    ``relationships``, not in any binary_report field.
    """
    arts = [
        ObservedArtifact(
            label=IoCLabel.OTHER,
            value="cluster.id.0001 — see relationships",
        )
    ]
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(
            overview=_valid_overview(),
            behavior=_valid_behavior(),
            observed_artifacts=arts,
        )


# ── 6. Length budget ──────────────────────────────────────────────────


def test_total_length_below_minimum_raises():
    """A report with a single tiny behavior section and an empty
    artifacts list renders well under 1500 chars and must fail the
    length validator.
    """
    with pytest.raises(ValidationError, match="rendered length"):
        BinaryReport(
            overview=_valid_overview(),
            behavior=[
                BehaviorSection(
                    heading="Token enumeration",
                    body="Reads a few values.",
                ),
            ],
            observed_artifacts=[],
        )


def test_total_length_above_maximum_raises():
    """Inflate one body so the rendered total clears the 4500 char
    cap and confirm the validator catches it.
    """
    huge_body = "Writes data to disk in a loop. " * 200  # ~6 KB
    with pytest.raises(ValidationError, match="rendered length"):
        BinaryReport(
            overview=_valid_overview(),
            behavior=[
                BehaviorSection(
                    heading="Disk staging via standard CRT IO",
                    body=huge_body,
                )
            ],
            observed_artifacts=[],
        )


# ── 7. Outer-model serializer flattening ──────────────────────────────


def test_cluster_analysis_response_dumps_binary_report_as_markdown_string():
    """ClusterAnalysisResponse.model_dump() must expose binary_report
    as the rendered markdown string, not the structured dict — every
    downstream consumer (HTML report builder, IDA view) reads it as a
    string.
    """
    report = _valid_report()
    response = ClusterAnalysisResponse(
        clusters=[_valid_cluster_item()],
        binary_description=(
            "Credential stealer that harvests wallet and mail-client "
            "configuration values."
        ),
        binary_category=BinaryCategory.CREDENTIAL_STEALER,
        binary_report=report,
    )
    dumped = response.model_dump()
    assert "binary_report" in dumped
    assert isinstance(dumped["binary_report"], str), type(dumped["binary_report"])
    assert dumped["binary_report"] == report.to_markdown()
    # The legacy cluster-map flattening is unchanged.
    assert isinstance(dumped["clusters"], dict)
    assert "cluster_1" in dumped["clusters"]
