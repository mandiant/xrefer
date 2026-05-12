"""Unit tests for the structured ``BinaryReport`` Pydantic model and
its outer-model serializer.

The schema deliberately has only two fields — ``overview`` and
``details`` — to give the LLM a consistent top-level structure
without forcing it into narrow per-section observations. The earlier
schema (``behavior: List[BehaviorSection]`` + structured
``observed_artifacts``) was removed because it pushed the LLM toward
narrow verb-phrase headings and suppressed the comprehensive
synthesizing narrative style analyst-grade triage uses.

Tests cover:

* Structural rules: overview opener, non-empty fields.
* Banned tokens: marketing adjectives + ``cluster.id.`` are rejected.
* Hedge tokens (``likely``, ``appears to``, ``may``) are INTENTIONALLY
  allowed — the originals (origin/main, origin/gsoc_2025) use them in
  their own framing.
* Length is INTENTIONALLY not validated — short reports and long
  reports both instantiate; the soft target lives in the LLM-visible
  docstring + a post-hoc log warning in ClusterAnalyzer.
* Outer-model serializer flattens BinaryReport → markdown string.
"""

import pytest
from pydantic import ValidationError

from xrefer.llm.dspy_modules import (
    BinaryCategory,
    BinaryReport,
    ClusterAnalysisItem,
    ClusterAnalysisResponse,
    MitreAttackTechnique,
)


# ── Fixture helpers ───────────────────────────────────────────────────


def _valid_overview() -> str:
    """A representative overview that satisfies the opener rule."""
    return (
        "The binary is a credential stealer that systematically harvests "
        "system metadata and application configuration data and "
        "exfiltrates results to a remote HTTP endpoint. It uses standard "
        "Windows APIs for data collection and the WinHttp library for "
        "exfiltration."
    )


def _valid_details() -> str:
    """A rich details body modeled on real analyst triage reports."""
    return (
        "### Execution and Orchestration\n"
        "\n"
        "The binary's execution begins with an orchestration layer that "
        "initialises the environment and manages the transition between "
        "primary modules. It establishes exception handling routines "
        "and uses a mutex named `filemanager1` to ensure only a single "
        "instance runs on the host.\n"
        "\n"
        "### Information Stealing and Data Collection\n"
        "\n"
        "The core functionality lives in a dedicated data-collection "
        "engine that performs:\n"
        "\n"
        "- **System Discovery**: Retrieves the computer name, current "
        "username, OS version, and physical memory status via "
        "`GetComputerNameW`, `GetUserNameW`, and `GlobalMemoryStatusEx`.\n"
        "- **Storage and Environment Enumeration**: Identifies all "
        "logical drives and maps standard system folders (Desktop, "
        "AppData) to locate target files.\n"
        "- **Application Targeting**: Searches the registry for "
        "configuration data tied to high-value applications.\n"
        "\n"
        "### Network Communication and Exfiltration\n"
        "\n"
        "Exfiltration runs over HTTP via the WinHttp library. The "
        "malware communicates with the domain `tastedata.shop`, POSTing "
        "collected data to the PHP endpoint `/ag-ap.php`. Requests use "
        "a hardcoded User-Agent string mimicking a macOS Chrome browser.\n"
        "\n"
        "### Indicators of Compromise (IoCs)\n"
        "\n"
        "- **Domain**: `tastedata.shop`\n"
        "- **URL Path**: `/ag-ap.php`\n"
        "- **Mutex**: `filemanager1`\n"
    )


def _valid_report(**overrides) -> BinaryReport:
    """Build a BinaryReport that passes every validator. Tests override
    individual fields to exercise specific failure modes.
    """
    kwargs = dict(
        overview=_valid_overview(),
        details=_valid_details(),
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
    # Top-level structure is fixed: `## Overview` then `## Details`.
    assert md.startswith("## Overview\n")
    assert "\n## Details\n" in md
    h2 = [line for line in md.splitlines() if line.startswith("## ")]
    assert h2 == ["## Overview", "## Details"]
    # The details body's `###` sub-headings come through verbatim.
    h3 = [line for line in md.splitlines() if line.startswith("### ")]
    assert "### Execution and Orchestration" in h3
    assert "### Indicators of Compromise (IoCs)" in h3


def test_to_markdown_renders_overview_then_details():
    """``to_markdown`` always emits `## Overview` then `## Details`
    with the LLM-supplied overview / details bodies interleaved.
    """
    r = BinaryReport(
        overview="The binary is a test fixture.",
        details="### Section\n\nbody.\n",
    )
    md = r.to_markdown()
    assert (
        md
        == "## Overview\n\nThe binary is a test fixture.\n\n## Details\n\n### Section\n\nbody.\n"
    )


# ── 2. Missing / empty fields ─────────────────────────────────────────


def test_missing_overview_raises():
    with pytest.raises(ValidationError):
        BinaryReport(details=_valid_details())


def test_missing_details_raises():
    with pytest.raises(ValidationError):
        BinaryReport(overview=_valid_overview())


# ── 3. Wrong opener ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_opener",
    [
        # Length is no longer validated, so these can be any length.
        # We only care that the opener-validator rule
        # ("must open with The binary is / This binary is") fires.
        "This is a binary that spreads through phishing-attached zip files.",
        "The sample is a Windows credential stealer.",
        "It is a tiny dropper that stages a second-stage payload on disk.",
        "Analysis: this binary is a credential stealer.",  # opener not at start
    ],
)
def test_overview_opener_validator(bad_opener):
    with pytest.raises(ValidationError, match="open with"):
        BinaryReport(overview=bad_opener, details=_valid_details())


@pytest.mark.parametrize(
    "good_opener_prefix",
    ["The binary is ", "This binary is "],
)
def test_overview_opener_accepts_both_canonical_forms(good_opener_prefix):
    overview = good_opener_prefix + "a test fixture."
    BinaryReport(overview=overview, details=_valid_details())


# ── 4. Banned tokens — marketing adjectives + cluster.id. only ────────
#
# Hedges (likely / appears to / may / etc.) are INTENTIONALLY ALLOWED.
# origin/main and origin/gsoc_2025 both use these tokens in their own
# instructions to the LLM; analyst triage prose uses hedges to signal
# inference vs. direct observation. The banned-token list is now just
# marketing adjectives + the `cluster.id.` cross-cluster leak.


@pytest.mark.parametrize(
    "adjective",
    [
        "sophisticated",
        "advanced",
        "powerful",
        "comprehensive",
        "extensive",
        "robust",
        "complex",
        "specialized",
        "distinctive",
    ],
)
def test_marketing_adjective_in_overview_raises(adjective):
    bad = f"The binary is a {adjective} credential stealer."
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(overview=bad, details=_valid_details())


def test_marketing_adjective_in_details_raises():
    bad_details = (
        "### Section\n\nThe sophisticated unpacker stages a payload in memory.\n"
    )
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(overview=_valid_overview(), details=bad_details)


def test_cluster_id_leak_in_details_raises():
    """The literal substring ``cluster.id.`` belongs in per-cluster
    ``relationships``, not in binary_report.
    """
    bad_details = "### Section\n\nDelegates to cluster.id.0042 for encryption.\n"
    with pytest.raises(ValidationError, match="banned token"):
        BinaryReport(overview=_valid_overview(), details=bad_details)


# ── 5. Hedge tokens are ALLOWED ───────────────────────────────────────


@pytest.mark.parametrize(
    "hedge_phrase",
    [
        "The screen capture likely facilitates surveillance.",
        "The persistence mechanism appears to set a registry run-key.",
        "The encryption may use AES in CBC mode.",
        "The path-walking routine seems to enumerate user directories.",
        "Reading this file possibly indicates a configuration step.",
        "The behaviour suggests credential harvesting.",
    ],
)
def test_hedge_tokens_are_allowed_in_details(hedge_phrase):
    """Hedges signal inference vs. observation. They were briefly
    banned and that was a mistake — analyst-grade prose uses them.
    """
    details = f"### Section\n\n{hedge_phrase}\n"
    BinaryReport(overview=_valid_overview(), details=details)


def test_hedge_token_in_overview_is_allowed():
    overview = "The binary is likely a credential stealer based on its targeted registry queries and HTTP exfiltration endpoints."
    BinaryReport(overview=overview, details=_valid_details())


# ── 6. Length is NOT validated ───────────────────────────────────────


def test_terse_short_overview_is_accepted():
    """A short overview (well under what used to be the 200-char
    floor) MUST instantiate without raising. Real-world small/simple
    binaries can be described in a single short sentence.
    """
    short_overview = "The binary is a CRC32 utility that prints the checksum of its argument."
    BinaryReport(overview=short_overview, details="### Computes a CRC32.\n\nReads bytes, computes, prints.\n")


def test_terse_short_details_is_accepted():
    """A short details body for a simple binary should not raise."""
    BinaryReport(
        overview=_valid_overview(),
        details="### Computes a CRC32.\n\nReads bytes, computes, prints.\n",
    )


def test_long_report_is_accepted():
    """A long report (over what used to be the 4500-char ceiling)
    MUST instantiate without raising. The HTML renderer is happy
    with long markdown; the soft maximum exists only as a triage
    hint via ClusterAnalyzer's post-hoc warning, not a hard limit.
    """
    huge_details = "### Disk staging\n\n" + ("Writes data to disk in a loop. " * 200)
    r = BinaryReport(overview=_valid_overview(), details=huge_details)
    assert len(r.to_markdown()) > BinaryReport.SOFT_MAX_LENGTH


def test_soft_length_constants_exist():
    """Sanity-check that the SOFT_MIN_LENGTH / SOFT_MAX_LENGTH
    constants are still available — they're consumed by
    ClusterAnalyzer._warn_on_sparse_binary_report for the post-hoc
    log-warning band.
    """
    assert isinstance(BinaryReport.SOFT_MIN_LENGTH, int)
    assert isinstance(BinaryReport.SOFT_MAX_LENGTH, int)
    assert BinaryReport.SOFT_MIN_LENGTH < BinaryReport.SOFT_MAX_LENGTH


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
