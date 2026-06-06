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
    BinarySynthesisResponse,
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


# ── 4. Banned tokens are NOT validated ───────────────────────────────
#
# Earlier iterations enforced a marketing-adjective + cluster.id. ban
# via a @model_validator on BinaryReport that raised. That validator
# caused real analyses to abort when the LLM used a single banned word
# in an otherwise-rich report. The ban is now a SOFT post-hoc warning
# in ClusterAnalyzer._warn_on_sparse_binary_report — the prompt asks
# the LLM to prefer concrete facts; the warning surfaces slips.
# Hedge tokens (likely / appears to / may) were never the right thing
# to ban — origin/main and origin/gsoc_2025 use them in their own
# framing and analyst prose uses them to signal inference.


@pytest.mark.parametrize(
    "adjective",
    [
        "sophisticated", "advanced", "powerful", "comprehensive",
        "extensive", "robust", "complex", "specialized", "distinctive",
    ],
)
def test_marketing_adjective_in_overview_is_accepted(adjective):
    """Marketing adjectives in overview are accepted (validator
    removed). The post-hoc warning in cluster_analyzer logs the
    slip without aborting the analysis.
    """
    overview = f"The binary is a {adjective} credential stealer that exfiltrates harvested data."
    BinaryReport(overview=overview, details=_valid_details())


def test_marketing_adjective_in_details_is_accepted():
    bad_details = (
        "### Section\n\nThe sophisticated unpacker stages a payload in memory.\n"
    )
    BinaryReport(overview=_valid_overview(), details=bad_details)


def test_cluster_id_leak_in_details_is_accepted():
    """``cluster.id.NNNN`` should not appear in binary_report
    (belongs in per-cluster relationships) — but appearance is a
    post-hoc warning, not a validation failure."""
    bad_details = "### Section\n\nDelegates to cluster.id.0042 for encryption.\n"
    BinaryReport(overview=_valid_overview(), details=bad_details)


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
    """Hedges signal inference vs. observation. Analyst-grade prose
    uses them; the originals (main, gsoc_2025) use them too.
    """
    details = f"### Section\n\n{hedge_phrase}\n"
    BinaryReport(overview=_valid_overview(), details=details)


def test_hedge_token_in_overview_is_allowed():
    overview = "The binary is likely a credential stealer based on its targeted registry queries and HTTP exfiltration endpoints."
    BinaryReport(overview=overview, details=_valid_details())


# ── 4b. The post-hoc warning helper ──────────────────────────────────


def test_warn_helper_logs_on_marketing_adjective(monkeypatch):
    """The post-hoc helper in ClusterAnalyzer should log a warning
    when marketing adjectives slip through, but never raise.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []

    def fake_log(msg: str) -> None:
        captured.append(msg)

    monkeypatch.setattr("xrefer.llm.cluster_analyzer.log", fake_log)
    ClusterAnalyzer._warn_on_sparse_binary_report(
        "## Overview\n\nThe binary is a sophisticated credential stealer.\n\n"
        "## Details\n\n### Section\n\nBody with `cmd.exe`.\n"
    )
    assert any("marketing adjective 'sophisticated'" in m for m in captured), captured


def test_warn_helper_logs_on_cluster_id_leak(monkeypatch):
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(
        "## Overview\n\nThe binary is a stealer.\n\n"
        "## Details\n\n### Section\n\nDelegates to cluster.id.0042.\n"
    )
    assert any("cluster.id." in m for m in captured), captured


def test_warn_helper_flags_puffery_in_binary_description(monkeypatch):
    """The post-hoc helper should also scan ``binary_description``
    (the standalone summary, separate from binary_report) for
    marketing adjectives. ``binary_description`` is the marquee
    summary line shown in the HTML report and the IDA cluster
    header, so puffery there is especially visible.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    desc = (
        "The binary is a sophisticated ransomware payload that "
        "orchestrates a complex lifecycle of credential theft."
    )
    # Pass an otherwise-clean report so only the description warning fires.
    md = (
        "## Overview\n\nThe binary is a fixture.\n\n"
        "## Details\n\n### Section\n\nbody.\n"
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(
        md, binary_description=desc
    )
    desc_msgs = [m for m in captured if "binary_description" in m]
    # Both 'sophisticated' and 'complex' are in BANNED_TOKENS_SOFT.
    tokens_flagged = {tok for tok in ("sophisticated", "complex")
                      if any(tok in m for m in desc_msgs)}
    assert tokens_flagged == {"sophisticated", "complex"}, (
        tokens_flagged, desc_msgs
    )


def test_warn_helper_silent_on_clean_binary_description(monkeypatch):
    """A binary_description free of banned tokens produces no
    binary_description warning.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    desc = "The binary is a ransomware that encrypts files using ChaCha20-Poly1305."
    md = (
        "## Overview\n\nThe binary is a fixture.\n\n"
        "## Details\n\n### Section\n\nbody.\n"
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(
        md, binary_description=desc
    )
    desc_msgs = [m for m in captured if "binary_description" in m]
    assert desc_msgs == [], desc_msgs


def test_warn_helper_flags_unresolved_citation(monkeypatch):
    """When a citation references a cluster ID that isn't in the
    binary's cluster set, the post-hoc helper logs a warning. The
    web UI is expected to degrade gracefully on these (rendering a
    broken-link chip) so the warning is informational, not fatal.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    md = (
        "## Overview\n\nThe binary is a test fixture.\n\n"
        "## Details\n\n### Section\n\n"
        "Does the thing [c5]. Does another thing [c5, c99].\n"
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(
        md, valid_cluster_ids={1, 5}
    )
    assert any("c99" in m for m in captured), captured
    # c5 is valid, so it should NOT appear in the unresolved warning.
    unresolved_msgs = [m for m in captured if "not present" in m]
    assert len(unresolved_msgs) == 1, unresolved_msgs
    assert "c5" not in unresolved_msgs[0]


def test_warn_helper_silent_on_resolved_citations(monkeypatch):
    """All cited cluster IDs exist in the valid set → no warning."""
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    md = (
        "## Overview\n\nThe binary is a test fixture.\n\n"
        "## Details\n\n### Section\n\n"
        "Does the thing [c5]. And another [c1, c5, c7].\n"
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(
        md, valid_cluster_ids={1, 5, 7, 12}
    )
    unresolved_msgs = [m for m in captured if "not present" in m]
    assert unresolved_msgs == [], unresolved_msgs


def test_warn_helper_skips_citation_check_when_valid_ids_none(monkeypatch):
    """Callers that don't have the cluster tree handy can omit the
    ``valid_cluster_ids`` parameter; the citation check is then a
    no-op (length and banned-token checks still run).
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    md = (
        "## Overview\n\nThe binary is a test fixture.\n\n"
        "## Details\n\n### Section\n\nDoes the thing [c99].\n"
    )
    ClusterAnalyzer._warn_on_sparse_binary_report(md)  # no valid_cluster_ids
    unresolved_msgs = [m for m in captured if "not present" in m]
    assert unresolved_msgs == [], unresolved_msgs


def test_citation_regex_matches_documented_forms():
    """The class-level citation regex must match every form documented
    in BinaryReport.details and split out the IDs correctly.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    cases = [
        ("Does X [c5].", [5]),
        ("Does X [c4, c6].", [4, 6]),
        ("Does X [c4, c6, c7].", [4, 6, 7]),
        ("Does X [c4,c6].", [4, 6]),  # whitespace after comma is optional
        ("Does X [c10] and Y [c2, c30].", [10, 2, 30]),
    ]
    for text, expected_ids in cases:
        found: list[int] = []
        for bracket in ClusterAnalyzer._CITATION_GROUP_RE.finditer(text):
            for inner in ClusterAnalyzer._CITATION_ID_RE.finditer(bracket.group(0)):
                found.append(int(inner.group(1)))
        assert found == expected_ids, (text, found, expected_ids)


def test_citation_regex_ignores_non_citation_brackets():
    """The regex must not match unrelated bracketed content —
    markdown links, generic numbered footnotes, lone letters, etc.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer

    non_citations = [
        "[link text](https://example.com)",
        "[1]",            # missing `c` prefix
        "[c]",            # missing digit
        "[Section A]",    # arbitrary bracketed text
        "[c5",            # unterminated
        "c5]",            # not bracketed
    ]
    for text in non_citations:
        matches = list(ClusterAnalyzer._CITATION_GROUP_RE.finditer(text))
        assert matches == [], (text, matches)


def test_warn_helper_silent_on_clean_report(monkeypatch):
    """A clean (no marketing adjectives, no cluster.id.) report
    of sufficient length should produce NO warning.
    """
    from xrefer.llm.cluster_analyzer import ClusterAnalyzer
    from xrefer.llm.dspy_modules import BinaryReport

    captured: list[str] = []
    monkeypatch.setattr(
        "xrefer.llm.cluster_analyzer.log", lambda msg: captured.append(msg)
    )
    # Pad a clean report so it's between SOFT_MIN_LENGTH and
    # SOFT_MAX_LENGTH so neither length warning fires either.
    body = "Body text with concrete facts and `code spans`. " * 40
    md = (
        "## Overview\n\nThe binary is a test fixture.\n\n"
        "## Details\n\n### Section\n\n" + body + "\n"
    )
    assert BinaryReport.SOFT_MIN_LENGTH <= len(md) <= BinaryReport.SOFT_MAX_LENGTH
    ClusterAnalyzer._warn_on_sparse_binary_report(md)
    assert captured == [], captured


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
#
# The cluster analysis flow is two-stage: stage 1 returns a
# ``ClusterAnalysisResponse`` with per-cluster fields only, and stage
# 2 returns a ``BinarySynthesisResponse`` with the binary-level fields
# (``binary_description``, ``binary_category``, ``binary_report``).
# Each model has its own serializer; the tests below cover both.


def test_cluster_analysis_response_serializes_clusters_as_map():
    """``ClusterAnalysisResponse.model_dump()`` flattens the ordered
    list of per-cluster items into the legacy ``cluster_id`` →
    ``cluster fields`` dict shape that downstream consumers
    (analyzer.find_cluster_analysis, the HTML report, the IDA view)
    expect.
    """
    response = ClusterAnalysisResponse(clusters=[_valid_cluster_item()])
    dumped = response.model_dump()
    assert isinstance(dumped["clusters"], dict)
    assert "cluster_1" in dumped["clusters"]
    # The legacy shape no longer carries binary-level fields — those
    # are emitted by ``BinarySynthesisResponse`` (see next test).
    assert "binary_report" not in dumped
    assert "binary_description" not in dumped
    assert "binary_category" not in dumped


def test_binary_synthesis_response_dumps_binary_report_as_markdown_string():
    """``BinarySynthesisResponse.model_dump()`` must expose
    ``binary_report`` as the rendered markdown string, not the
    structured dict — every downstream consumer (HTML report builder,
    IDA cluster header, analyzer.generate_report_data) reads it as a
    string.
    """
    report = _valid_report()
    response = BinarySynthesisResponse(
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
    assert dumped["binary_description"].startswith("Credential stealer")
    # ``binary_category`` may come through as either the enum instance
    # or its string value depending on Pydantic config; downstream
    # ``analyzer._normalize_category_value`` accepts both. Use the
    # same form-agnostic check here.
    cat = dumped["binary_category"]
    assert getattr(cat, "value", cat) == BinaryCategory.CREDENTIAL_STEALER.value
