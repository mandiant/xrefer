# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the bare-bones markdown renderer used to display the
LLM ``binary_report`` in IDA's custom viewer. Targets the pure,
IDA-free parser in ``xrefer.core.helpers`` (the SCOLOR mapping lives in
the gui layer and is verified in IDA, not here)."""

from xrefer.core.helpers import render_markdown_segments, strip_cluster_citations


def _styles(seg_line):
    return [style for style, _ in seg_line]


def _visible_len(seg_line):
    return sum(len(text) for _, text in seg_line)


def _plain_text(seg_line):
    return "".join(text for _, text in seg_line)


def test_empty_input_returns_empty():
    assert render_markdown_segments("") == []
    assert render_markdown_segments("   \n\n  ") == []


def test_heading_levels_map_to_styles():
    out = render_markdown_segments("## Overview", width=80)
    # h2 heading line + an underline line
    assert ("h2", "Overview") in [(s, t) for line in out for s, t in line]
    assert any("h2" in _styles(line) and set(_plain_text(line)) == {"─"} for line in out), \
        "expected an h2 underline rule line"

    out3 = render_markdown_segments("### Capabilities", width=80)
    assert any("h3" in _styles(line) for line in out3)
    # h3 is not underlined
    assert not any(set(_plain_text(line)) == {"─"} for line in out3)

    out4 = render_markdown_segments("#### Notes", width=80)
    assert any("h4" in _styles(line) for line in out4)


def test_bullets_get_marker_and_content():
    out = render_markdown_segments("- first item\n- second item", width=80)
    bullet_lines = [line for line in out if "bullet" in _styles(line)]
    assert len(bullet_lines) == 2
    # marker glyph then the content words
    assert bullet_lines[0][0] == ("plain", "")  # depth-0 lead is empty
    assert ("bullet", "• ") in bullet_lines[0]
    assert "first" in _plain_text(bullet_lines[0])


def test_nested_bullet_indented():
    out = render_markdown_segments("- top\n  - nested", width=80)
    nested = [line for line in out if "nested" in _plain_text(line)][0]
    # nested bullet carries a 2-space lead before the glyph
    assert nested[0] == ("plain", "  ")


def test_ordered_list_marker_preserved():
    out = render_markdown_segments("1. alpha\n2. beta", width=80)
    markers = [t for line in out for s, t in line if s == "bullet"]
    assert markers == ["1. ", "2. "]


def test_inline_bold_and_code_segments():
    out = render_markdown_segments("Uses **VirtualAlloc** then calls `WriteFile` now", width=120)
    flat = [(s, t) for line in out for s, t in line]
    assert ("bold", "VirtualAlloc") in flat
    assert ("code", "WriteFile") in flat
    # markers are stripped from the rendered text
    assert "**" not in _plain_text(out[0])
    assert "`" not in _plain_text(out[0])


def test_paragraph_wraps_to_width():
    para = " ".join(["word%02d" % i for i in range(40)])  # 40 * 7 chars-ish
    width = 40
    out = render_markdown_segments(para, width=width)
    assert len(out) > 1  # actually wrapped
    for line in out:
        assert _visible_len(line) <= width, f"line exceeds width: {_plain_text(line)!r}"


def test_long_word_not_dropped():
    blob = "x" * 200
    out = render_markdown_segments(blob, width=40)
    assert _plain_text(out[0]) == blob  # oversized token kept intact on its own line


def test_blank_lines_collapse_and_trim():
    out = render_markdown_segments("\n\n## A\n\n\n\nbody text\n\n", width=80)
    # no leading or trailing blank separator lines
    assert out[0] != []
    assert out[-1] != []
    # at most one consecutive blank separator anywhere
    for idx in range(len(out) - 1):
        assert not (out[idx] == [] and out[idx + 1] == [])


def test_horizontal_rule_becomes_rule_line():
    out = render_markdown_segments("above\n\n---\n\nbelow", width=30)
    assert any("rule" in _styles(line) and set(_plain_text(line)) == {"─"} for line in out)


def test_realistic_report_renders_without_error():
    md = (
        "## Overview\n\n"
        "The sample is a **downloader** that retrieves a second stage over HTTPS.\n\n"
        "## Details\n\n"
        "### Network\n\n"
        "- Resolves the C2 via `getaddrinfo`\n"
        "- Connects with `WSAConnect`\n\n"
        "### Persistence\n\n"
        "Writes a run key using `RegSetValueExW`.\n\n"
        "### Indicators of Compromise (IoCs)\n\n"
        "- `hxxps://evil.example/stage2`\n"
    )
    out = render_markdown_segments(md, width=70)
    assert out  # produced something
    heading_texts = [t for line in out for s, t in line if s in ("h2", "h3")]
    assert "Overview" in heading_texts
    assert "Details" in heading_texts
    assert "Network" in heading_texts
    # every line stays within width
    for line in out:
        assert _visible_len(line) <= 70


# -- cluster-citation stripping ------------------------------------------


def test_strip_single_citation_and_preceding_space():
    assert strip_cluster_citations("survives reboot [c5].") == "survives reboot."
    assert strip_cluster_citations("buffer[c5]") == "buffer"


def test_strip_multi_cluster_citations():
    assert strip_cluster_citations("alpha [c4, c6] beta") == "alpha beta"
    assert strip_cluster_citations("x [c2, c4, c5].") == "x."
    # no-space comma variant
    assert strip_cluster_citations("y [c4,c6] z") == "y z"


def test_strip_multiple_citations_in_one_string():
    assert strip_cluster_citations("foo [c1] bar [c2].") == "foo bar."


def test_strip_is_case_insensitive():
    assert strip_cluster_citations("foo [C5] bar") == "foo bar"


def test_non_citations_are_preserved():
    # not cluster citations -> must be left intact
    assert strip_cluster_citations("see [important] note") == "see [important] note"
    assert strip_cluster_citations("ref [1] here") == "ref [1] here"
    assert strip_cluster_citations("the [cat] sat") == "the [cat] sat"
    assert strip_cluster_citations("bracket [c] only") == "bracket [c] only"


def test_strip_empty_and_none_safe():
    assert strip_cluster_citations("") == ""
    assert strip_cluster_citations("no citations here") == "no citations here"


def test_render_drops_citations_via_strip_then_parse():
    md = "### Network\n\n- Resolves the C2 via `getaddrinfo` [c4, c6]\n"
    out = render_markdown_segments(strip_cluster_citations(md), width=80)
    flat_text = " ".join(t for line in out for _, t in line)
    assert "c4" not in flat_text and "c6" not in flat_text
    assert "[" not in flat_text
    assert "getaddrinfo" in flat_text
