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

"""Tests for the grep.app -> Grep MCP string-enrichment rewrite.

grep.app was rebuilt on Vercel behind a bot challenge; the enrichment now calls
the official Grep MCP server's ``searchGitHub`` tool and parses its formatted
text blocks. These tests cover the pure parsers (SSE extraction, one block ->
repo/path/matched_lines with reconstructed line numbers, the content -> repos
mapping incl. the no-results / empty sentinels) and an end-to-end run of
``enrich_string_data_core`` with the network call monkeypatched — exercising the
threading, the >5-occurrence repo heuristic, the 50-char trim, and the
7-tuple output. No network, no IDA.
"""

import xrefer.core.helpers as helpers
from xrefer.core.helpers import (
    _extract_mcp_json,
    _grep_mcp_repositories_from_content,
    _parse_grep_result_block,
    enrich_string_data_core,
)

# A representative searchGitHub text block (two snippets, one with blank lines).
_BLOCK_FOO = (
    "Repository: foo/bar\n"
    "Path: src/lib.rs\n"
    "URL: https://github.com/foo/bar/blob/main/src/lib.rs\n"
    "License: MIT\n"
    "\n"
    "Snippets:\n"
    "--- Snippet 1 (Line 10) ---\n"
    "fn main() {\n"
    '    println!("hello");\n'
    "}\n"
    "\n"
    "--- Snippet 2 (Line 42) ---\n"
    "let x = compute();\n"
)
_BLOCK_BAZ = (
    "Repository: baz/qux\n"
    "Path: README.md\n"
    "URL: https://github.com/baz/qux/blob/main/README.md\n"
    "License: Unknown\n"
    "\n"
    "Snippets:\n"
    "--- Snippet 1 (Line 1) ---\n"
    "# title\n"
)


def _content(*texts):
    return [{"type": "text", "text": t} for t in texts]


# --------------------------------------------------------------------------- #
# _extract_mcp_json — pull JSON-RPC out of the SSE stream
# --------------------------------------------------------------------------- #
def test_extract_mcp_json_from_sse():
    raw = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n\n'
    assert _extract_mcp_json(raw) == {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}


def test_extract_mcp_json_takes_last_data_line():
    raw = 'data: {"a":1}\ndata: {"b":2}\n'
    assert _extract_mcp_json(raw) == {"b": 2}


def test_extract_mcp_json_plain_body():
    assert _extract_mcp_json('{"x":3}') == {"x": 3}


def test_extract_mcp_json_garbage_returns_none():
    assert _extract_mcp_json("not json at all") is None


# --------------------------------------------------------------------------- #
# _parse_grep_result_block — one repo block -> (repo, path, matched_lines)
# --------------------------------------------------------------------------- #
def test_parse_block_basic():
    repo, repo_path, matched = _parse_grep_result_block(_BLOCK_FOO)
    assert repo == "foo/bar"
    assert repo_path == "foo/bar/src/lib.rs"
    # Line numbers reconstructed from each snippet's start; blank lines dropped.
    assert matched == {
        "10": "fn main() {",
        "11": '    println!("hello");',
        "12": "}",
        "42": "let x = compute();",
    }


def test_parse_block_no_repository_returns_none():
    assert _parse_grep_result_block("Path: x\nSnippets:\n") is None


# --------------------------------------------------------------------------- #
# _grep_mcp_repositories_from_content — content list -> repos dict / sentinels
# --------------------------------------------------------------------------- #
def test_repositories_from_content_multi():
    repos = _grep_mcp_repositories_from_content(_content(_BLOCK_FOO, _BLOCK_BAZ))
    assert set(repos) == {"foo/bar", "baz/qux"}
    assert repos["foo/bar"]["path"] == "foo/bar/src/lib.rs"
    assert repos["baz/qux"]["matched_lines"] == {"1": "# title"}


def test_repositories_no_results_sentinel():
    repos = _grep_mcp_repositories_from_content(_content("No results found for your query."))
    assert repos == {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}


def test_repositories_empty_content():
    assert _grep_mcp_repositories_from_content([]) == {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}


# --------------------------------------------------------------------------- #
# enrich_string_data_core — full run with the network call monkeypatched
# --------------------------------------------------------------------------- #
_LONG = "this is a sufficiently long binary string number {}"  # >30 chars


def test_enrich_end_to_end_repo_selected(monkeypatch):
    # Every string resolves to foo/bar -> occurrence count exceeds the >5 gate.
    monkeypatch.setattr(helpers, "_grep_mcp_search", lambda *a, **k: _content(_BLOCK_FOO))
    strings = [_LONG.format(i) for i in range(6)]
    out = enrich_string_data_core(list(range(6)), list(strings), lookup=True)
    for i, tup in enumerate(out):
        repo, shown, etype, path, matched, all_repos, full = tup
        assert repo == "foo/bar"
        assert etype == 3
        assert path == "foo/bar/src/lib.rs"
        assert matched["10"] == "fn main() {"
        assert all_repos == ["foo/bar/src/lib.rs"]
        assert full == strings[i]
        assert shown == strings[i][:50]  # trimmed display string


def test_enrich_heuristic_requires_more_than_five(monkeypatch):
    # Only 3 strings share foo/bar -> count (3) <= 5 -> stays UNCATEGORIZED,
    # but all_repos is still populated from the lookup.
    monkeypatch.setattr(helpers, "_grep_mcp_search", lambda *a, **k: _content(_BLOCK_FOO))
    strings = [_LONG.format(i) for i in range(3)]
    out = enrich_string_data_core(list(range(3)), list(strings), lookup=True)
    for tup in out:
        assert tup[0] == "UNCATEGORIZED"
        assert tup[5] == ["foo/bar/src/lib.rs"]


def test_enrich_short_strings_skip_lookup(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("short strings must not hit the network")

    monkeypatch.setattr(helpers, "_grep_mcp_search", _boom)
    out = enrich_string_data_core([0, 1], ["short", "also short"], lookup=True)
    assert all(tup[0] == "UNCATEGORIZED" for tup in out)


def test_enrich_lookup_disabled_skips_network(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("lookup=False must not hit the network")

    monkeypatch.setattr(helpers, "_grep_mcp_search", _boom)
    out = enrich_string_data_core([0], [_LONG.format(0)], lookup=False)
    assert out[0][0] == "UNCATEGORIZED"
