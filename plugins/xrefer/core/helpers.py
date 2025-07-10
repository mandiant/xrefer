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

import html
import os
import platform
import queue
import re
import threading
import unicodedata
from collections import defaultdict
from time import time
from typing import Any, Dict, List, Optional, Tuple, Union

import networkx as nx
import requests
from bs4 import BeautifulSoup
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


def _enrich_string_data(str_indexes: List[int], entity_list: List[str], lookup: bool = True, max_threads: int = 50) -> List[Tuple[str, str, int, str, dict, list]]:
    """
    Enrich string information by searching in Git repositories.

    Performs parallel queries to grep.app API to find string usage in public repositories.
    Enriches strings with repository context and matched code lines.

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
    url = "https://grep.app/api/search"
    total_strings = len(str_indexes)
    input_queue = queue.Queue()
    result_queue = queue.Queue()
    threads = []
    repo_data_by_index = {}

    # Enqueue all string indices to be processed
    for str_index in str_indexes:
        input_queue.put(str_index)

    def parse_snippet(snippet):
        matches = {}
        soup = BeautifulSoup(snippet, "html.parser")

        for row in soup.find_all("tr"):
            # Extract the line number
            lineno_div = row.find("div", class_="lineno")
            if not lineno_div:
                continue
            line_number = lineno_div.get_text(strip=True)

            # Extract the code line HTML
            code_pre = row.find("pre")
            if not code_pre:
                continue
            code_line_html = code_pre.decode_contents()

            # Replace <mark> tags with placeholders
            code_line_html = re.sub(r"<mark[^>]*>", "", code_line_html)
            code_line_html = code_line_html.replace("</mark>", "")

            # Unescape HTML entities
            code_line_html = html.unescape(code_line_html)

            # We remove tags like <span> but keep their content and whitespace
            code_line_text = re.sub(r"</?(?!mark\b)[^>]*>", "", code_line_html)
            matches[line_number] = code_line_text

        return matches

    def fetch_repositories(search_string):
        """
        Fetch repositories from the API for the given string.

        Args:
            search_string (str): The string to search for in repositories.

        Returns:
            dict: A dictionary mapping repository names to details:
                  {
                      repo_name: {
                          'path': repo_path,
                          'matched_lines': matched_lines
                      },
                      ...
                  }
                  Returns {'UNCATEGORIZED': {'path': '', 'matched_lines': {}}} if no repositories are found or an error occurs.
        """
        if len(search_string) <= 30:
            return {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}

        params = {
            "q": search_string,
            "page": 1,
            "case": "true",  # Making the search case-sensitive
            "format": "e",  # Extended result format
        }

        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                return {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}
            repositories = {}
            for hit in hits:
                repo_name = hit["repo"]["raw"]
                path = hit["path"]["raw"]
                snippet = hit["content"]["snippet"]
                matched_lines = parse_snippet(snippet)
                repositories[repo_name] = {"path": f"{repo_name}/{path}", "matched_lines": matched_lines}
            return repositories
        except (requests.RequestException, ValueError):
            return {"UNCATEGORIZED": {"path": "", "matched_lines": {}}}

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
    ss, i = "", 0
    while i < size:
        if s[i] == "\x00":
            break
        ss += s[i]
        i += 1
    return ss, i


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


def log(string: str) -> None:
    """
    Log message with XRefer prefix.

    This is a backend-agnostic logging function that prints to stdout.
    Backend-specific implementations can override or extend this behavior.

    Args:
        string (str): Message to log
    """
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
