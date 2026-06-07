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

import json
import os
import platform
import queue
import re
import threading
import unicodedata
from collections import defaultdict
from time import sleep, time
from typing import Any, Dict, List, Optional, Tuple, Union

import networkx as nx
import requests
from requests.adapters import HTTPAdapter
from tabulate import tabulate


def check_internet_connectivity(timeout: float = 3.0) -> bool:
    """
    Quick check for internet connectivity using reliable hosts.
    Uses a very short timeout for fast failure.

    Args:
        timeout: Maximum time to wait for response in seconds

    Returns:
        bool: True if internet is available, False otherwise
    """
    test_urls = [
        "https://8.8.8.8",  # Google DNS
        "https://1.1.1.1",  # Cloudflare DNS
    ]

    for url in test_urls:
        try:
            requests.get(url, timeout=timeout)
            return True
        except requests.RequestException:
            continue
    return False


# --- grep.app code search -------------------------------------------------
# grep.app was rebuilt on Vercel behind a bot challenge ("Vercel Security
# Checkpoint", HTTP 429 + x-vercel-mitigated: challenge) that blocks the old
# `GET https://grep.app/api/search?...&format=e` endpoint the original
# enrichment relied on. The supported programmatic interface is now the
# official **Grep MCP server** (stateless MCP-over-HTTP), which is NOT
# challenged. We call its single `searchGitHub` tool and parse the formatted
# text blocks it returns (one per repo: Repository / Path / URL / License +
# numbered code Snippets). See project memory for the full analysis.
_GREP_MCP_ENDPOINT = "https://mcp.grep.app"
_GREP_MCP_TOOL = "searchGitHub"
_GREP_MIN_QUERY_LEN = 30        # don't look up short / noisy strings
# Values tuned against the live MCP endpoint (see project memory). Observed
# behaviour: the backend has a heavy tail — a *successful* search returns in
# <=3s (p99 ~3.0s) but a sizeable, load-varying fraction hangs to Vercel's
# ~15s gateway timeout and 504s; retrying a hung query almost always succeeds
# fast. So: a SHORT timeout to fail-fast on the hangs (well above the 3s
# success p99) + generous retries for coverage (a lost lookup => an
# UNCATEGORIZED string). Concurrency 8-12 is the sweet spot; >=16 induces
# *more* hangs, so don't crank it.
_GREP_MCP_MAX_THREADS = 12      # 8-12 optimal; higher induces more 504s
_GREP_MCP_TIMEOUT = 8           # seconds; > success-p99 (~3s), << gateway 504 (~15s)
_GREP_MCP_RETRIES = 4           # hangs are transient + recover fast; favour coverage
_GREP_MCP_BACKOFF = 0.5         # linear backoff base between retries (s)

_GREP_RE_REPO = re.compile(r"^Repository:\s*(.+)$", re.M)
_GREP_RE_PATH = re.compile(r"^Path:\s*(.+)$", re.M)
_GREP_RE_SNIPPET = re.compile(r"^--- Snippet \d+ \(Line (\d+)\) ---$", re.M)

_GREP_UNCATEGORIZED = {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}

# One pooled HTTPS Session reused across all worker threads, so the many
# searches reuse TCP/TLS connections instead of a fresh handshake per call.
# requests.Session is thread-safe for concurrent .post(); the pool is sized to
# the worker count to avoid "connection pool is full" churn. Lazily created.
_grep_session: Optional[requests.Session] = None
_grep_session_lock = threading.Lock()


def _get_grep_session() -> requests.Session:
    """Return the process-wide pooled Session for MCP calls (created once)."""
    global _grep_session
    if _grep_session is None:
        with _grep_session_lock:
            if _grep_session is None:
                session = requests.Session()
                adapter = HTTPAdapter(
                    pool_connections=_GREP_MCP_MAX_THREADS,
                    pool_maxsize=_GREP_MCP_MAX_THREADS,
                )
                session.mount("https://", adapter)
                session.mount("http://", adapter)
                _grep_session = session
    return _grep_session


def _extract_mcp_json(raw: str) -> Optional[dict]:
    """Pull the JSON-RPC object out of a streamable-HTTP MCP response.

    The Grep MCP server replies as an SSE stream (``event: message`` /
    ``data: {json}``); we take the last ``data:`` payload. Falls back to
    treating the whole body as plain JSON. Returns ``None`` if nothing parses.
    """
    data_payloads = [ln[len("data:"):].strip() for ln in raw.splitlines() if ln.startswith("data:")]
    candidate = data_payloads[-1] if data_payloads else raw.strip()
    try:
        return json.loads(candidate)
    except (ValueError, TypeError):
        return None


def _grep_mcp_search(query: str, match_case: bool = True, timeout: int = _GREP_MCP_TIMEOUT, retries: int = _GREP_MCP_RETRIES) -> list:
    """Call the Grep MCP ``searchGitHub`` tool; return its ``content`` list
    (each item a text block) or ``[]`` on error / no JSON-RPC result.

    A literal, optionally case-sensitive code search (``useRegexp`` left at its
    default of false, so a string with regex-special characters needs no
    escaping). One JSON-RPC POST per query over the shared pooled session;
    transient failures (504 hangs cut short by the timeout, or an unparseable
    body) are retried with linear backoff. A genuine JSON-RPC ``error`` is NOT
    retried.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": _GREP_MCP_TOOL, "arguments": {"query": query, "matchCase": bool(match_case)}},
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "xrefer",
    }
    session = _get_grep_session()
    for attempt in range(retries + 1):
        try:
            response = session.post(_GREP_MCP_ENDPOINT, json=payload, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = _extract_mcp_json(response.text)
            if data is None:
                raise requests.RequestException("unparseable MCP response")  # transient → retry
            if "error" in data:
                return []  # genuine RPC error (not transient) — don't retry
            return data.get("result", {}).get("content", []) or []
        except requests.RequestException:
            if attempt < retries:
                sleep(_GREP_MCP_BACKOFF * (attempt + 1))  # linear backoff before retrying
            continue
    return []


def _parse_grep_result_block(text: str) -> Optional[Tuple[str, str, dict]]:
    """Parse one ``searchGitHub`` text block into ``(repo, repo_path, matched_lines)``.

    ``matched_lines`` is ``{lineno: code_line}`` reconstructed by numbering each
    snippet's code lines from its ``--- Snippet N (Line L) ---`` start line
    (the server gives only the first line number per snippet). Returns ``None``
    when the block has no ``Repository:`` header.
    """
    repo_match = _GREP_RE_REPO.search(text)
    if not repo_match:
        return None
    repo = repo_match.group(1).strip()
    path_match = _GREP_RE_PATH.search(text)
    path = path_match.group(1).strip() if path_match else ""

    matched_lines: Dict[str, str] = {}
    # split() with the capturing group yields: [prefix, line1, body1, line2, body2, ...]
    parts = _GREP_RE_SNIPPET.split(text)
    for i in range(1, len(parts) - 1, 2):
        try:
            start = int(parts[i])
        except ValueError:
            continue
        body = parts[i + 1].strip("\n")
        for offset, code_line in enumerate(body.splitlines()):
            if code_line.strip():
                matched_lines[str(start + offset)] = code_line
    return repo, f"{repo}/{path}", matched_lines


def _grep_mcp_repositories_from_content(content: list) -> dict:
    """Convert an MCP ``searchGitHub`` ``content`` list into the legacy
    ``{repo_name: {'path':..., 'matched_lines':...}}`` mapping, or the
    ``UNCATEGORIZED`` sentinel when there are no usable results.
    """
    if not content:
        return {k: dict(v) for k, v in _GREP_UNCATEGORIZED.items()}
    # Server's explicit no-results reply.
    if len(content) == 1 and "No results found" in content[0].get("text", ""):
        return {k: dict(v) for k, v in _GREP_UNCATEGORIZED.items()}

    repositories: Dict[str, dict] = {}
    for item in content:
        if item.get("type") != "text":
            continue
        parsed = _parse_grep_result_block(item.get("text", ""))
        if not parsed:
            continue
        repo, repo_path, matched_lines = parsed
        repositories[repo] = {"path": repo_path, "matched_lines": matched_lines}
    return repositories or {k: dict(v) for k, v in _GREP_UNCATEGORIZED.items()}


def enrich_string_data_core(str_indexes: List[int], entity_list: List[str], lookup: bool = True, max_threads: int = _GREP_MCP_MAX_THREADS) -> List[Tuple[str, str, int, str, dict, list]]:
    """
    Enrich string information by searching public GitHub code.

    Performs parallel queries to the Grep MCP server (``searchGitHub`` tool —
    the supported successor to the old grep.app HTTP API) to find string usage
    in public repositories, enriching strings with repository context and
    matched code lines.

    Args:
        str_indexes (List[int]): List of string indexes to process
        entity_list (List[str]): List of strings to enrich
        lookup (bool): Whether to perform Git lookups
        max_threads (int): Maximum number of threads for parallel processing

    Returns:
        List[Tuple[str, str, int, str, dict, list]]: List of enriched string information tuples:
            - repo_name: Name of selected repository or 'UNCATEGORIZED'
            - original_string: Original string content
            - entity_type: Constant value 3 (strings)
            - repo_path: Path in selected repository
            - matched_lines: Dictionary mapping line numbers to code lines
            - all_repos: List of all repositories where string was found
    """
    total_strings = len(str_indexes)
    input_queue = queue.Queue()
    result_queue = queue.Queue()
    threads = []
    repo_data_by_index = {}

    # Enqueue all string indices to be processed
    for str_index in str_indexes:
        input_queue.put(str_index)

    def fetch_repositories(search_string):
        """Look ``search_string`` up via the Grep MCP server.

        Returns ``{repo_name: {'path': repo_path, 'matched_lines': {...}}}``,
        or ``{'UNCATEGORIZED': {'path': '', 'matched_lines': {}}}`` for short
        strings, no results, or any error.
        """
        if len(search_string) <= _GREP_MIN_QUERY_LEN:
            return {k: dict(v) for k, v in _GREP_UNCATEGORIZED.items()}
        content = _grep_mcp_search(search_string, match_case=True)
        return _grep_mcp_repositories_from_content(content)

    def worker():
        """
        Worker thread function to process strings from the input queue.
        """
        while True:
            try:
                str_index = input_queue.get_nowait()
            except queue.Empty:
                break  # Exit the loop if the queue is empty
            search_string = entity_list[str_index]
            if not search_string:
                # Handle empty strings
                repositories = {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}
            elif lookup:
                repositories = fetch_repositories(search_string)
            else:
                repositories = {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}
            result_queue.put((str_index, repositories))
            input_queue.task_done()

    # Start worker threads
    num_threads = min(max_threads, total_strings)
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Wait until all tasks are processed
    input_queue.join()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Collect results from worker threads
    while not result_queue.empty():
        str_index, repositories = result_queue.get()
        repo_data_by_index[str_index] = repositories

    # Count repository occurrences across all strings
    repo_occurrences = defaultdict(int)
    for repositories in repo_data_by_index.values():
        for repo_name in repositories:
            repo_occurrences[repo_name] += 1

    # Update entity_list with the selected repository information
    for str_index, repositories in repo_data_by_index.items():
        max_count = 0
        candidate_repos = []
        selected_repo = None
        full_search_string = entity_list[str_index]
        entity_list[str_index] = full_search_string[:50]  # trim strings to first 50 characters
        search_string = entity_list[str_index]
        all_repos = [f"{repo_data['path']}" for repo_name, repo_data in repositories.items() if repo_name != "UNCATEGORIZED"]

        for repo_name, repo_info in repositories.items():
            count = repo_occurrences[repo_name]
            if count > 5:
                if count > max_count:
                    candidate_repos = [(repo_name, repo_info)]
                    max_count = count
                elif count == max_count:
                    candidate_repos.append((repo_name, repo_info))
        if candidate_repos:
            # Select the repo with the shortest path
            min_path_length = None
            selected_candidate = None
            for repo_name, repo_info in candidate_repos:
                path_components = repo_info["path"].split("/")
                path_length = len(path_components)
                if (min_path_length is None) or (path_length < min_path_length):
                    min_path_length = path_length
                    selected_candidate = (repo_name, repo_info)
            # Now set selected_repo using selected_candidate
            repo_name, repo_info = selected_candidate
            selected_repo = (repo_name, search_string, 3, repo_info["path"], repo_info["matched_lines"], all_repos, full_search_string)
        else:
            selected_repo = ("UNCATEGORIZED", search_string, 3, "", {}, all_repos, full_search_string)
        entity_list[str_index] = selected_repo

    return entity_list


def convert_int_to_hex(value: Union[int, str]) -> str:
    """
    Convert integer or string value to hexadecimal representation.

    Args:
        value (Union[int, str]): Value to convert. If already a string, returned unchanged.

    Returns:
        str: Hexadecimal string representation prefixed with '0x' if input was integer,
             otherwise original string value.
    """
    if isinstance(value, int):
        return f"0x{value:x}"
    return value


def normalize_path(path: str) -> str:
    """
    Normalize a file path by resolving '..' and standardizing separators.

    Args:
        path (str): File path to normalize

    Returns:
        str: Normalized path with standardized directory separators and resolved '..' segments
    """
    if ".." not in path:
        return path

    path = path.replace("\\", os.sep).replace("/", os.sep)
    normalized_path = os.path.normpath(path)
    return normalized_path


def cap_artifact_entries(
    per_type: List[Tuple[str, List[Tuple[str, int]]]],
    cap: Optional[int],
    overflow_color,
    overflow_fmt: str = "(+{count} more)",
) -> List[Tuple[str, int]]:
    """Flatten per-type graph-node artifact entries, capping each type to ``cap``.

    ``per_type`` is an ordered list of ``(type_key, [(display_text, color), ...])``
    (e.g. imports/strings/capa/libs, in display order). When ``cap`` is a positive
    int and a type has more than ``cap`` entries, only the first ``cap`` are kept
    and a single ``overflow_fmt`` line (coloured ``overflow_color``) is appended
    for that type. ``cap`` of ``None`` / ``<= 0`` means no cap — every entry passes
    through, which is the default (show-all) behaviour. Pure and backend-agnostic:
    the overflow colour is supplied by the caller so this stays free of IDA deps.
    """
    out: List[Tuple[str, int]] = []
    for _key, items in per_type:
        if cap is None or cap <= 0 or len(items) <= cap:
            out.extend(items)
        else:
            out.extend(items[:cap])
            out.append((overflow_fmt.format(count=len(items) - cap), overflow_color))
    return out


def wrap_substring_with_string(string: str, substring: str, substr_1: str, substr_2: Optional[str] = None, case: bool = False) -> str:
    """
    Wrap occurrences of a substring within a string with given wrapper strings.

    Args:
        string (str): The original string to process
        substring (str): The substring to find and wrap
        substr_1 (str): String to prepend to found substring
        substr_2 (Optional[str]): String to append to found substring. If None, substr_1 is used
        case (bool): Whether to perform case-sensitive search

    Returns:
        str: Modified string with substring wrapped with given strings
    """
    if case:
        start = string.find(substring)
    else:
        start = string.lower().find(substring.lower())
    if start >= 0:
        end = start + len(substring)
        if substr_2:
            return string[:start] + substr_1 + string[start:end] + substr_2 + string[end:]
        else:
            return string[:start] + substr_1 + string[start:end] + substr_1 + string[end:]
    return string


def remove_non_displayable(s: str) -> str:
    """
    Remove non-displayable characters from string.

    Args:
        s (str): Input string containing potential non-displayable characters

    Returns:
        str: String with non-displayable characters removed
    """
    return "".join(c for c in s if unicodedata.category(c)[0] != "C")


def filter_null_string(s: str, size: int) -> Tuple[str, int]:
    """
    Filter null bytes from string and calculate actual length.

    Args:
        s (str): Input string potentially containing null bytes
        size (int): Maximum size to check

    Returns:
        Tuple[str, int]: Filtered string and its actual length
    """
    limit = min(size, len(s))
    for i, ch in enumerate(s[:limit]):
        if ch == "\x00":
            return s[:i], i
    return s[:limit], limit


def longest_line_length(s: Optional[str]) -> int:
    """
    Calculate length of longest line in multi-line string.

    Args:
        s (Optional[str]): Input string, possibly None

    Returns:
        int: Length of longest line, 0 if input is None or empty
    """
    if s is None or s == "\n" * len(s):
        return 0
    else:
        return max(len(line) for line in s.split("\n"))


def word_wrap_text(text: str, width: int) -> List[str]:
    """
    Word wrap text to specified width.

    Args:
        text: Text to wrap
        width: Maximum width for each line

    Returns:
        List of wrapped lines
    """
    if not text:
        return []

    words = text.split()
    lines = []
    current_line = []
    current_length = 0

    for word in words:
        word_length = len(word)
        if current_length + word_length + len(current_line) <= width:
            current_line.append(word)
            current_length += word_length
        else:
            if current_line:
                lines.append(" ".join(current_line))
            current_line = [word]
            current_length = word_length

    if current_line:
        lines.append(" ".join(current_line))

    return lines


# MARKDOWN RENDERING (bare-bones, IDA-free)
#
# The ``binary_report`` produced by the LLM is a constrained markdown
# subset: ``##``/``###``/``####`` ATX headings, ``-``/``*`` and ``N.``
# lists, ``**bold**`` and ``code`` inline spans, and blank-line
# separated paragraphs (see llm/dspy_modules.py:BinaryReport). This
# renderer turns that markdown into a flat list of "segment lines" --
# each line is a list of ``(style, text)`` tuples -- so a frontend (the
# IDA custom viewer) can map styles to its own coloring without
# re-parsing. Pure Python: no IDA, no third-party deps.

_MD_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_MD_BULLET_RE = re.compile(r"^(\s*)[-*]\s+(.*)$")
_MD_ORDERED_RE = re.compile(r"^(\s*)(\d+)\.\s+(.*)$")
_MD_HRULE_RE = re.compile(r"^\s*([-*_])(?:\s*\1){2,}\s*$")
_MD_INLINE_RE = re.compile(r"\*\*.+?\*\*|`[^`]+`")

# Style vocabulary emitted by render_markdown_segments(); a frontend
# maps each of these to its own styling. An empty segment line ([])
# denotes a blank line.
MD_STYLES = ("plain", "bold", "code", "h2", "h3", "h4", "bullet", "rule")


def _strip_inline_markers(text: str) -> str:
    """Drop inline ``**`` and `````` markers, keeping the inner text."""
    return text.replace("**", "").replace("`", "")


def _parse_inline_markdown(text: str) -> List[Tuple[str, str]]:
    """Split a run of text into ``(style, text)`` segments, recognising
    ``**bold**`` and ``code`` spans. Unmatched markers stay plain."""
    segments: List[Tuple[str, str]] = []
    pos = 0
    for m in _MD_INLINE_RE.finditer(text):
        if m.start() > pos:
            segments.append(("plain", text[pos:m.start()]))
        token = m.group(0)
        if token.startswith("**"):
            segments.append(("bold", token[2:-2]))
        else:
            segments.append(("code", token[1:-1]))
        pos = m.end()
    if pos < len(text):
        segments.append(("plain", text[pos:]))
    return segments


def _wrap_styled_segments(segments: List[Tuple[str, str]], width: int) -> List[List[Tuple[str, str]]]:
    """Greedy word-wrap styled segments to ``width`` visible columns.
    Returns a list of lines, each a list of ``(style, text)`` segments
    with single-space ``("plain", " ")`` separators between words."""
    words: List[Tuple[str, str]] = []
    for style, txt in segments:
        for word in txt.split():
            words.append((style, word))
    if not words:
        return [[("plain", "")]]

    lines: List[List[Tuple[str, str]]] = []
    cur: List[Tuple[str, str]] = []
    cur_len = 0
    for style, word in words:
        wlen = len(word)
        if cur and cur_len + 1 + wlen > width:
            lines.append(cur)
            cur, cur_len = [], 0
        if cur:
            cur.append(("plain", " "))
            cur_len += 1
        cur.append((style, word))
        cur_len += wlen
    if cur:
        lines.append(cur)
    return lines


def render_markdown_segments(md: str, width: int = 80) -> List[List[Tuple[str, str]]]:
    """Render the ``binary_report`` markdown subset into styled segment
    lines.

    Each output line is a list of ``(style, text)`` tuples where style
    is one of :data:`MD_STYLES`; an empty list denotes a blank line.
    ``width`` controls word-wrapping of paragraphs and list items. No
    IDA dependency -- the frontend maps styles to colors.
    """
    if not md or not md.strip():
        return []
    width = max(20, int(width))
    src = md.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: List[List[Tuple[str, str]]] = []

    def emit_blank() -> None:
        # Collapse runs of blank lines into a single separator.
        if out and out[-1] != []:
            out.append([])

    i, n = 0, len(src)
    while i < n:
        line = src[i].rstrip()
        if not line.strip():
            emit_blank()
            i += 1
            continue

        if _MD_HRULE_RE.match(line):
            out.append([("rule", "─" * width)])
            i += 1
            continue

        hm = _MD_HEADING_RE.match(line)
        if hm:
            level = len(hm.group(1))
            style = "h2" if level <= 2 else ("h3" if level == 3 else "h4")
            text = _strip_inline_markers(hm.group(2))
            out.extend(_wrap_styled_segments([(style, text)], width))
            if level <= 2:
                # Underline h1/h2 section headers for a clear visual break.
                out.append([("h2", "─" * min(width, len(text)))])
            i += 1
            continue

        bm = _MD_BULLET_RE.match(line)
        om = _MD_ORDERED_RE.match(line) if not bm else None
        if bm or om:
            if bm:
                indent_spaces = len(bm.group(1))
                glyph = "• "
                content = bm.group(2)
            else:
                indent_spaces = len(om.group(1))
                glyph = f"{om.group(2)}. "
                content = om.group(3)
            depth = indent_spaces // 2
            lead = "  " * depth
            hang = len(lead) + len(glyph)
            wrapped = _wrap_styled_segments(_parse_inline_markdown(content), max(10, width - hang))
            for idx, wl in enumerate(wrapped):
                if idx == 0:
                    out.append([("plain", lead), ("bullet", glyph)] + wl)
                else:
                    out.append([("plain", " " * hang)] + wl)
            i += 1
            continue

        # Paragraph: gather consecutive non-blank, non-block lines and
        # re-wrap them as one flowing block.
        para = [line]
        i += 1
        while i < n:
            nxt = src[i].rstrip()
            if (not nxt.strip()
                    or _MD_HEADING_RE.match(nxt)
                    or _MD_BULLET_RE.match(nxt)
                    or _MD_ORDERED_RE.match(nxt)
                    or _MD_HRULE_RE.match(nxt)):
                break
            para.append(nxt)
            i += 1
        out.extend(_wrap_styled_segments(_parse_inline_markdown(" ".join(para)), width))

    # Trim leading/trailing blank separators.
    while out and out[0] == []:
        out.pop(0)
    while out and out[-1] == []:
        out.pop()
    return out


# Cluster citations like ``[c5]`` / ``[c4, c6]`` / ``[c2, c4, c5]`` are
# emitted in the binary_report for the HTML renderer, where they link to
# clusters. In the plain IDA viewer they are noise, so strip them before
# rendering. See llm/dspy_modules.py for the citation token spec.
_CLUSTER_CITATION_RE = re.compile(r"\s*\[\s*c\d+(?:\s*,\s*c\d+)*\s*\]", re.IGNORECASE)


def strip_cluster_citations(text: str) -> str:
    """Remove cluster-citation tokens (``[c5]``, ``[c4, c6]``,
    ``[c2, c4, c5]``) from report text.

    These citations are only meaningful in the HTML report, where they
    resolve to cluster links; in the plain IDA custom viewer they add
    noise, so they are stripped before markdown rendering. A single
    space immediately preceding a citation is consumed too, so
    ``"... survives reboot [c1, c91]."`` renders as
    ``"... survives reboot."``.
    """
    if not text:
        return text
    return _CLUSTER_CITATION_RE.sub("", text)


# COLOR CODE AND DISPLAY UTILITIES


def strip_color_codes(text: str) -> str:
    """
    Remove all IDA color codes from text while preserving content.

    Color codes in IDA follow the pattern \x01CODE and \x02CODE where CODE is a color
    identifier. This function removes these sequences to get actual visible text length.

    Args:
        text: String potentially containing IDA color codes

    Returns:
        String with all color codes removed
    """
    return re.sub(r"\x01[\x00-\xff]|\x02[\x00-\xff]", "", text)


def calculate_padding(text: str, desired_length: int) -> int:
    """
    Calculate required padding to achieve desired visible length accounting for color codes.

    Since color codes affect string length but not visible length, this calculates
    the padding needed to make visible content match desired length.

    Args:
        text: Text containing potential color codes
        desired_length: Target visible length

    Returns:
        Number of spaces needed for padding
    """
    visible_length = len(strip_color_codes(text))
    return max(0, desired_length - visible_length)


def get_visible_width(text: str) -> int:
    """
    Calculate the visible width of text by excluding color codes.

    Used for proper column width calculations and alignment. Only counts
    characters that will actually render on screen.

    Args:
        text: Text to measure

    Returns:
        Width of text as it appears on screen
    """
    return len(re.sub(r"\x01[\x00-\xff]|\x02[\x00-\xff]", "", text))


def get_addr_from_text(text: str) -> int:
    """
    Extract address from text containing IDA color codes.

    Parses text containing an address, removing color codes and formatting
    to extract the raw address value.

    Args:
        text (str): Text containing address with potential color codes

    Returns:
        int: Extracted address value

    Raises:
        ValueError: If text doesn't contain valid hex address
    """
    addr: int = int(text.strip(" │\x04\x10\x18\t").strip(), base=16)
    return addr


# TABLE CREATION UTILITIES


def create_table_from_rows(headings: List[str], rows: List[List[Any]]) -> str:
    """
    Create a formatted text table from headings and row data.

    Args:
        headings (List[str]): List of column headers
        rows (List[List[Any]]): List of rows, where each row is a list of values

    Returns:
        str: Formatted table as string with proper alignment and borders using
             tabulate library
    """
    rows = [[convert_int_to_hex(value) for value in row] for row in rows]
    max_row_length = max(len(row) for row in rows)

    if len(headings) < max_row_length:
        headings += [""] * (max_row_length - len(headings))

    table = tabulate(rows, headers=headings, tablefmt="simple")
    return table


def create_table_from_cols(headings: List[str], columns: List[List[Any]]) -> str:
    """
    Create a formatted text table from headings and column data.

    Transposes column data into rows and creates properly formatted table.
    Handles columns of unequal length by padding shorter columns with empty strings.

    Args:
        headings (List[str]): List of column headers
        columns (List[List[Any]]): List of columns, where each column is a list of values

    Returns:
        str: Formatted table as string with proper alignment and borders
    """
    max_column_length = max(len(column) for column in columns)
    rows = []
    for i in range(max_column_length):
        row = []
        for column in columns:
            if i < len(column):
                row.append(column[i])
            else:
                row.append("")
        rows.append(row)

    table = tabulate(rows, headers=headings, tablefmt="simple")
    return table


# =============================================================================
# PLATFORM AND GRAPH UTILITIES
# =============================================================================


def is_windows_or_linux() -> bool:
    """
    Check if current platform is Windows or Linux.

    Used for platform-specific UI adjustments.

    Returns:
        bool: True if platform is Windows or Linux
    """
    _platform = platform.system().lower()
    return _platform in ("windows", "linux")


def create_graph(paths: List[List[int]], entity: str) -> nx.DiGraph:
    """
    Create NetworkX directed graph from paths.

    Converts list of address paths into graph structure suitable
    for ASCII visualization.

    Args:
        paths (List[List[int]]): List of address paths
        entity (str): Name of target entity for path endpoints

    Returns:
        nx.DiGraph: Directed graph representing paths to entity
    """
    # TODO: add full function names
    _graph = nx.DiGraph()

    for path in paths:
        for i in range(len(path) - 1):
            if i == 0:
                _graph.add_edge(f"ENTRYPOINT\n0x{path[i]:x}", f"0x{path[i + 1]:x}")
            else:
                _graph.add_edge(f"0x{path[i]:x}", f"0x{path[i + 1]:x}")
        _graph.add_edge(f"0x{path[-1]:x}", entity)

    return _graph


# =============================================================================
# CLUSTER ANALYSIS UTILITIES
# =============================================================================


def parse_cluster_id(word: str) -> Optional[int]:
    """
    Parse cluster ID from text, finding core pattern 'cluster.id.xxxx' anywhere.
    Also handles bracketed format '[xxxx]'.

    Args:
        word: Text that may contain a cluster ID

    Returns:
        Optional[int]: Parsed cluster ID, or None if no valid ID found

    Examples:
        >>> parse_cluster_id("cluster.id.0001")
        1
        >>> parse_cluster_id("Some text cluster.id.0002 more text")
        2
        >>> parse_cluster_id("│cluster.id.0003│")
        3
        >>> parse_cluster_id("[0004]")
        4
        >>> parse_cluster_id("cluster_05")
        5
    """
    if not word:
        return None

    # Look for cluster.id.xxxx pattern anywhere in text
    match = re.search(r"cluster\.id\.(\d{4})", word)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass

    # Look for [xxxx] pattern
    match = re.search(r"\[(\d{4})\]", word)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass

    # Look for name_number pattern
    if "_" in word:
        try:
            return int(word.split("_")[1])
        except ValueError:
            pass

    return None


def find_cluster_analysis(analysis_data: Dict, cluster_id: str) -> Optional[Dict]:
    """Helper function to find cluster analysis data."""
    if not analysis_data or "clusters" not in analysis_data:
        return None

    cluster_data = analysis_data["clusters"]

    # Try different key formats (to account for varying LLM responses)
    potential_keys = [
        str(cluster_id),  # Direct ID
        f"cluster_{cluster_id}",  # With cluster_ prefix
        f"cluster_{int(cluster_id):02d}",  # With cluster_ prefix and padding 0n
        f"cluster_{int(cluster_id):03d}",  # With cluster_ prefix and padding 00n
        f"cluster_{int(cluster_id):04d}",  # With cluster_ prefix and padding 000n
        f"cluster.id.{int(cluster_id):04d}",  # cluster.id.xxxx
    ]

    for key in potential_keys:
        if key in cluster_data:
            return cluster_data[key]

    return None


def sanitize_dirtree_name(name: str, max_len: int = 64) -> str:
    """Sanitize a string for use as one component of an IDA dirtree
    (Functions-window) folder path.

    The dirtree uses ``/`` as its path separator, so a component must not
    contain one; backslashes, control characters and stray surrounding
    whitespace are also cleaned. Always returns a non-empty, length-bounded
    string. Pure string logic — no IDA dependency, so it lives in core.

    Args:
        name: Proposed folder-component name (e.g. a cluster label).
        max_len: Maximum length before truncation.

    Returns:
        A safe, non-empty folder-component name.
    """
    if not name:
        return "unnamed"
    # '/' and '\' are path separators in the dirtree — replace with a space.
    cleaned = name.replace("/", " ").replace("\\", " ")
    # Drop non-printable / control characters, then collapse whitespace runs.
    cleaned = "".join(ch if ch.isprintable() else " " for ch in cleaned)
    cleaned = " ".join(cleaned.split())
    # Trailing dots/spaces read oddly in tree views; strip them.
    cleaned = cleaned.strip().strip(".").strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip()
    return cleaned or "unnamed"


def sort_clusters(clusters, paths):
    """
    Sort clusters based on entry point reachability and parent/child relationships.

    Args:
        clusters: List of FunctionalCluster objects
        paths: Dictionary of paths to check for entry points

    Returns:
        List[FunctionalCluster]: Sorted list of clusters
    """

    def is_entry_point_reachable(cluster):
        """Check if cluster contains or can reach an entry point."""
        for node in cluster.nodes:
            # Check if node is an entry point
            if any(node == ep for ep in paths.keys()):
                return True
            # Check if node can reach an entry point
            for ep in paths.keys():
                if node in paths[ep]:
                    return True
        return False

    # Separate primary and secondary clusters
    primary_clusters = []
    secondary_clusters = []

    for cluster in clusters:
        if cluster.parent_cluster_id is None:
            primary_clusters.append(cluster)
        else:
            secondary_clusters.append(cluster)

    # Sort primary clusters - entry point reachable ones first
    sorted_primary = sorted(primary_clusters, key=lambda c: (not is_entry_point_reachable(c), c.id))

    # Sort secondary clusters by parent ID to maintain relationship grouping
    sorted_secondary = sorted(secondary_clusters, key=lambda c: (c.parent_cluster_id, c.id))

    return sorted_primary + sorted_secondary



_log_func = None

def set_log_function(func) -> None:
    """Set a custom log implementation used by core helpers.

    GUI or environment-specific frontends (e.g. IDA plugin) can call this
    at initialization to route all `log` calls through their own handler.
    """
    global _log_func
    _log_func = func

def log(string: str) -> None:
    """
    Log message with XRefer prefix.

    This is a backend-agnostic logging function that prints to stdout.
    Backend-specific implementations can override or extend this behavior.

    Args:
        string (str): Message to log
    """
    if _log_func is not None:
        _log_func(string)
    else:
        print(f"[XRefer] {string}")


def log_elapsed_time(msg: str, start_time: float) -> None:
    """
    Log elapsed time for an operation.

    Calculates and logs time elapsed since start_time in hours,
    minutes, and seconds format.

    Args:
        msg (str): Description of the operation
        start_time (float): Start time from time.time()
    """
    end_time = time()
    elapsed_time = end_time - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = int(elapsed_time % 60)
    log(f"[{msg}] {hours} hours, {minutes} minutes, {seconds} seconds")
