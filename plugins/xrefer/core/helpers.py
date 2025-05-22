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
import time
import unicodedata
from collections import defaultdict
from functools import wraps
from time import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import asciinet
import ida_bytes
import ida_idp
import ida_kernwin
import ida_lines
import ida_registry
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
import networkx as nx
import requests
from bs4 import BeautifulSoup
from PyQt5 import QtCore, QtGui, QtWidgets
from tabulate import tabulate


class FocusEventFilter(QtCore.QObject):
    """
    Event filter for handling focus events in XRefer view.

    Manages IDA shortcut overrides when XRefer view gains or loses focus
    to prevent conflicts with XRefer's keyboard handling.

    Attributes:
        xrefer_view: Reference to parent XRefer view instance
    """

    def __init__(self, xrefer_view):
        super().__init__()
        self.xrefer_view = xrefer_view

    def eventFilter(self, obj: Any, event: QtCore.QEvent) -> bool:
        """
        Filter focus events and manage shortcuts.

        Override or restore IDA shortcuts based on focus changes.

        Args:
            obj: Qt object receiving the event
            event: Qt event to filter

        Returns:
            bool: False to allow event propagation
        """
        if event.type() == QtCore.QEvent.FocusIn:
            self.xrefer_view.override_ida_shortcuts()
        elif event.type() == QtCore.QEvent.FocusOut:
            self.xrefer_view.restore_ida_shortcuts()
        return False  # Allow other handlers to process the event


class KeyEventFilter(QtCore.QObject):
    """
    Event filter for handling keyboard events in XRefer view.

    Captures and processes non-alphanumeric printable characters that
    Qt might otherwise not handle properly.

    Attributes:
        xrefer_view: Reference to parent XRefer view instance
    """

    def __init__(self, xrefer_view):
        super(KeyEventFilter, self).__init__()
        self.xrefer_view = xrefer_view  # Reference to the XReferView instance

    def eventFilter(self, obj: Any, event: QtCore.QEvent) -> bool:
        """
        Filter keyboard events for special character handling.

        Processes printable non-alphanumeric characters and passes them
        to XRefer's keyboard handler.

        Args:
            obj: Qt object receiving the event
            event: Qt event to filter

        Returns:
            bool: True if event was handled, False to allow propagation
        """
        if event.type() == QtCore.QEvent.KeyPress:
            _char = event.text()
            if _char and _char.isprintable() and not _char.isalnum():
                # Pass printable non-alphanumeric character to OnKeydown
                self.xrefer_view.OnKeydown(_char, False)
                event.accept()
                return True  # Accept the event to prevent further propagation

        return False  # Let other events propagate


class CollapseEventFilter(QtCore.QObject):
    def __init__(self, collapse_indicator):
        super().__init__()
        self.collapse_indicator = collapse_indicator
        self.reposition_timer = QtCore.QTimer()
        self.reposition_timer.setSingleShot(True)
        self.reposition_timer.timeout.connect(self.collapse_indicator.reposition)

    def eventFilter(self, obj, event):
        if event.type() in (QtCore.QEvent.Resize, QtCore.QEvent.Move):
            # Debounce repositioning to prevent rapid updates
            self.reposition_timer.start(50)
        elif event.type() == QtCore.QEvent.Hide:
            self.collapse_indicator.hide()
        elif event.type() == QtCore.QEvent.Show:
            self.reposition_timer.start(50)
        return False


class CollapseIndicator(QtWidgets.QWidget):
    def __init__(self, dock_widget, original_width):
        super().__init__(dock_widget)

        self.dock_widget = dock_widget
        self.is_collapsed = False
        self.original_width = original_width
        self.minimum_width = 400

        # Store positions
        self.last_expanded_x = None
        self.last_expanded_y = None
        self.last_expanded_width = None

        self.setup_ui()

        # Ensure indicator stays on top
        self.setWindowFlags(QtCore.Qt.ToolTip | QtCore.Qt.FramelessWindowHint)

        # Ensure indicator stays on top within the application
        self.setAttribute(QtCore.Qt.WA_AlwaysStackOnTop, True)

        # Connect to application focus changes
        QtWidgets.QApplication.instance().focusChanged.connect(self.on_focus_changed)

    def on_focus_changed(self, old, now):
        """Hide/show the indicator based on application focus."""
        active_window = QtWidgets.QApplication.activeWindow()
        if active_window is None:
            self.hide()
        else:
            self.show()

    def setup_ui(self):
        self.setFixedSize(20, 20)
        self.setStyleSheet("""
            QWidget {
                background-color: #2d2d2d;
                border-radius: 3px;
                border: 1px solid #3d3d3d;
            }
            QWidget:hover {
                background-color: #3d3d3d;
            }
        """)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.arrow_label = QtWidgets.QLabel("⟩")
        self.arrow_label.setStyleSheet("color: white; border: none;")
        self.arrow_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.arrow_label)

        self.setCursor(QtCore.Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self.toggle_collapsed()

    def toggle_collapsed(self):
        if not self.is_collapsed:
            # Store the expanded position and width before collapsing
            self.last_expanded_x = self.x()
            self.last_expanded_y = self.y()
            self.last_expanded_width = self.dock_widget.width()

            # Collapsing
            self.is_collapsed = True

            # Set minimum and maximum width to 0 to collapse
            self.dock_widget.setMinimumWidth(0)
            self.dock_widget.setMaximumWidth(0)
            self.arrow_label.setText("⟨")

            # Notify XReferView of collapse
            if hasattr(self.dock_widget, "xrefer_view"):
                self.dock_widget.xrefer_view.toggle_collapsed_state(True)
        else:
            # Expanding
            self.is_collapsed = False

            # Notify XReferView of expand
            if hasattr(self.dock_widget, "xrefer_view"):
                self.dock_widget.xrefer_view.toggle_collapsed_state(False)

            # Temporarily set minimum and maximum width to desired width to force expansion
            restore_width = self.last_expanded_width if self.last_expanded_width else self.original_width
            self.dock_widget.setMinimumWidth(restore_width)
            self.dock_widget.setMaximumWidth(restore_width)

            # Force the dock widget to adjust its size
            self.dock_widget.updateGeometry()

            # After a short delay, reset the size constraints to allow user resizing
            QtCore.QTimer.singleShot(100, self.reset_size_constraints)

            self.arrow_label.setText("⟩")

        # Update layouts
        self.dock_widget.updateGeometry()
        if self.dock_widget.widget():
            self.dock_widget.widget().updateGeometry()

        # Immediate reposition
        self.reposition()
        # Delayed reposition to ensure proper placement
        QtCore.QTimer.singleShot(50, self.reposition)

    def reset_size_constraints(self):
        """Reset size constraints to allow user resizing."""
        self.dock_widget.setMinimumWidth(0)
        self.dock_widget.setMaximumWidth(16777215)  # Qt's QWIDGETSIZE_MAX
        self.dock_widget.updateGeometry()

    def reposition(self):
        """Update the indicator position based on dock widget state."""
        if not self.dock_widget or not self.dock_widget.isVisible():
            self.hide()
            return

        try:
            # Get current dock position and screen
            dock_pos = self.dock_widget.mapToGlobal(QtCore.QPoint(0, 0))
            dock_geo = self.dock_widget.geometry()
            screen = QtWidgets.QApplication.screenAt(dock_pos)

            if not screen:  # Fallback to primary screen if screen not found
                screen = QtWidgets.QApplication.primaryScreen()

            screen_geo = screen.geometry()

            if self.is_collapsed:
                # When collapsed, use the last known expanded x position
                if self.last_expanded_x is not None:
                    x = self.last_expanded_x
                    y = self.last_expanded_y
                else:
                    # Fallback if no stored position
                    x = dock_pos.x() + dock_geo.width() - self.width() - 2
                    y = dock_pos.y() + (dock_geo.height() // 2) - (self.height() // 2)
            else:
                # When expanded, always position on the right edge
                x = dock_pos.x() + dock_geo.width() - self.width() - 2
                y = dock_pos.y() + (dock_geo.height() // 2) - (self.height() // 2)

                # Store this position
                self.last_expanded_x = x
                self.last_expanded_y = y
                self.last_expanded_width = dock_geo.width()

            # Ensure position is within screen bounds
            x = max(screen_geo.left(), min(x, screen_geo.right() - self.width()))
            y = max(screen_geo.top(), min(y, screen_geo.bottom() - self.height()))

            # Move to new position
            self.move(x, y)
            self.show()
            self.raise_()

        except Exception as e:
            log(f"Error in reposition: {str(e)}")

    def showEvent(self, event):
        super().showEvent(event)
        self.reposition()


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


def get_function_size(func_ea: int) -> int:
    """
    Calculate the size of a function in bytes.

    Args:
        func_ea (int): Effective address of function start

    Returns:
        int: Size of function in bytes (end_ea - start_ea)
    """
    end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    return end_ea - func_ea


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


def create_colored_table_from_cols(headings: List[str], columns: List[List[Any]], color_tag: int) -> List[str]:
    """
    Create a colored formatted table from headings and column data.

    Similar to create_table_from_cols but applies IDA color tags to the output.
    The first column is colored differently from the rest for visual distinction.

    Args:
        headings (List[str]): List of column headers
        columns (List[List[Any]]): List of columns, where each column is a list of values
        color_tag (int): IDA color tag to apply to the table

    Returns:
        List[str]: List of colored table rows as strings with IDA color codes
    """
    max_column_length = max(len(column) for column in columns)
    rows = []
    for i in range(max_column_length):
        row = []
        for column in columns:
            if i < len(column):
                row.append(convert_int_to_hex(column[i]))
            else:
                row.append("")
        rows.append(row)

    table = tabulate(rows, headers=headings, tablefmt="simple").splitlines()
    table_length = len(table)
    zeroth_col_length = len(table[1].split(" ")[0])

    for index in range(0, 2):
        table[index] = f"\x01{color_tag}{table[index]}\x02{color_tag}"

    for index in range(2, table_length):
        table[index] = f"\x01{ida_lines.SCOLOR_CREFTAIL}{table[index][:zeroth_col_length]}\x02{ida_lines.SCOLOR_CREFTAIL}\x01{color_tag}{table[index][zeroth_col_length:]}\x02{color_tag}"

    return table


def create_xrefs_table_colored(heading: str, xrefs_rows: List[List[Any]], color_tags: Union[int, Dict[int, List[int]]]) -> List[str]:
    """
    Create a colored cross-references table.

    Creates a table showing cross-references with appropriate coloring for different
    types of references (imports, strings, etc). Supports both single color and
    multi-color tables through color_tags parameter.

    Args:
        heading (str): Table heading text
        xrefs_rows (List[List[Any]]): List of cross-reference rows to display
        color_tags (Union[int, Dict[int, List[int]]]): Either a single color tag or
            a dictionary mapping color tags to row ranges

    Returns:
        List[str]: List of colored table rows as strings, including header and footer lines
    """
    _table = create_table_from_rows([heading], xrefs_rows).splitlines()
    zeroth_col_length = len(_table[1].split(" ")[0])
    table_length = len(_table)

    if not isinstance(color_tags, dict):
        for index in range(2, table_length):
            _table[index] = f"\x01{color_tags}{_table[index][:zeroth_col_length]}\x02{color_tags}{_table[index][zeroth_col_length:]}"
    else:
        for tag in color_tags.keys():
            for index in range(color_tags[tag][0], color_tags[tag][1]):
                _table[index] = f"\x01{tag}{_table[index][:zeroth_col_length]}\x02{tag}{_table[index][zeroth_col_length:]}"

    return [""] + _table + ["", ""]


def set_xref_coverage_color(line: str, xref_str: str, covered: bool = False) -> str:
    """
    Apply color to a cross-reference string based on coverage status.

    Args:
        line (str): The line containing the cross-reference
        xref_str (str): The cross-reference string to color
        covered (bool): Whether the cross-reference is covered by analysis

    Returns:
        str: Line with appropriate IDA color codes applied to the cross-reference string
    """
    if covered:
        line = line.replace(xref_str, ida_lines.COLSTR(xref_str, ida_lines.SCOLOR_LIBNAME))
    else:
        line = line.replace(xref_str, ida_lines.COLSTR(xref_str, ida_lines.SCOLOR_CREFTAIL))
    return line


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


def log(string: str) -> None:
    """
    Log message to IDA's output window with XRefer prefix.

    Also updates the wait box message if one is active.

    Args:
        string (str): Message to log
    """
    print(f"[XRefer] {string}")
    idaapi.replace_wait_box(f"HIDECANCEL\n{string}")


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


def enrich_string_data(str_indexes: List[int], entity_list: List[str], lookup: bool = True, max_threads: int = 50) -> List[Tuple[str, str, int, str, dict, list]]:
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
    if lookup:
        log("Querying strings in git repositories...")

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


def dump_indirect_calls(path: str) -> None:
    """
    Export list of indirect call sites to a file.

    Scans all functions in the IDB for indirect calls (calls through registers or memory)
    and writes their addresses to the specified file.

    Args:
        path (str): Output file path for the indirect calls list
    """
    indirect_calls = ""
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            for startea, endea in idautils.Chunks(funcea):
                for head in idautils.Heads(startea, endea):
                    if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                        if idaapi.is_call_insn(head):
                            insn = idaapi.insn_t()
                            idaapi.decode_insn(insn, head)
                            operand = insn.ops[0]
                            if operand.type in (idaapi.o_phrase, idaapi.o_displ, idaapi.o_reg):
                                indirect_calls += f"\n0x{head:x}"

    if indirect_calls:
        with open(path, "w") as outfile:
            outfile.write(indirect_calls)
        log(f"Dumped indirect calls to: {path}")


def handle_entrypoint_selection(plugin_instance: Any, custom_ep: int) -> bool:
    """
    Handle selection of a custom entry point for analysis.

    Validates the selected entry point and initiates either primary or secondary
    analysis based on current plugin state.

    Args:
        plugin_instance: Instance of XReferPlugin
        custom_ep (int): Address of selected entry point function

    Returns:
        bool: True if entry point was valid and analysis started, False otherwise
    """
    if custom_ep != idc.BADADDR:
        ep_name: str = idc.get_func_name(custom_ep)
        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.lang:
            log(f"Custom entrypoint selected for secondary analysis: 0x{custom_ep:x} ({ep_name})")
            plugin_instance.xrefer_view.xrefer_obj.current_analysis_ep = custom_ep
            plugin_instance.xrefer_view.xrefer_obj.run_standalone_secondary_analysis()
            plugin_instance.xrefer_view.update(True, ea=custom_ep)
        else:
            log(f"Custom entrypoint selected for primary analysis: 0x{custom_ep:x} ({ep_name})")
            if plugin_instance.xrefer_view:
                plugin_instance.xrefer_view.xrefer_obj.load_analysis()
                if plugin_instance.xrefer_view.xrefer_obj.lang:
                    plugin_instance.xrefer_view.create()
            else:
                plugin_instance.start(custom_ep)
        return True
    else:
        log("No valid function selected as entrypoint")
        return False


def colorize_api_call(input_string: str) -> str:
    """
    Apply IDA color codes to API call string.

    Parses and colorizes different components of API call string:
    - Arguments in parentheses
    - String values in quotes
    - Numeric values
    - Equal signs and operators

    Args:
        input_string (str): Raw API call string to colorize

    Returns:
        str: API call string with IDA color codes inserted

    Note:
        Handles nested structures and maintains proper color code nesting.
        Uses different colors for:
        - String values (SCOLOR_DSTR)
        - Numeric values (SCOLOR_CREFTAIL)
        - API names (SCOLOR_DEMNAME)
    """
    result = []
    length = len(input_string)
    i = 0
    in_value = False
    in_quotes = False
    quote_char = None
    param_count = 0
    equal_sign_present = False
    paren_depth = 0

    quoted_color_start = f"{ida_lines.SCOLOR_ON}{ida_lines.SCOLOR_DSTR}"
    quoted_color_end = f"{ida_lines.SCOLOR_OFF}{ida_lines.SCOLOR_DSTR}"
    non_quoted_color_start = f"{ida_lines.SCOLOR_ON}{ida_lines.SCOLOR_CREFTAIL}"
    non_quoted_color_end = f"{ida_lines.SCOLOR_OFF}{ida_lines.SCOLOR_CREFTAIL}"

    while i < length:
        char = input_string[i]

        if char == "(":
            paren_depth += 1
            result.append(char)
            i += 1
            continue
        elif char == ")":
            paren_depth -= 1
            if paren_depth == 0:
                # This is the final closing parenthesis
                if in_value:
                    result.append(quoted_color_end if in_quotes else non_quoted_color_end)
                    in_value = False
                result.append(char)
                break
            result.append(char)
            i += 1
            continue

        if not equal_sign_present and char == "=":
            equal_sign_present = True

        if equal_sign_present:
            if not in_value and char == "=":
                in_value = True
                result.append(char)
                i += 1
                if i < length and input_string[i] in ('"', "'"):
                    result.append(quoted_color_start)
                    in_quotes = True
                    quote_char = input_string[i]
                else:
                    result.append(non_quoted_color_start)
                continue

            if in_value:
                if in_quotes:
                    result.append(char)
                    if char == quote_char:
                        j = i + 1
                        while j < length and input_string[j] in (" ", "\t", "\n"):
                            j += 1
                        if j < length and input_string[j] in (",", ")"):
                            result.append(quoted_color_end)
                            in_quotes = False
                            in_value = False
                            i = j - 1
                else:
                    if char == ",":
                        result.append(non_quoted_color_end)
                        in_value = False
                    else:
                        result.append(char)
            else:
                result.append(char)
        else:
            if char == ",":
                if in_value:
                    result.append(non_quoted_color_end)
                    in_value = False
                param_count += 1
            elif param_count % 2 == 1 and char not in (" ", "\t", "\n", ","):
                if not in_value:
                    in_value = True
                    result.append(non_quoted_color_start)
                result.append(char)
            else:
                result.append(char)

        i += 1

    return ida_lines.COLSTR("".join(result), ida_lines.SCOLOR_DEMNAME)


def create_function_rows_for_interesting_artifacts(func_ea: int, artifacts: List[Tuple], xrefer_obj) -> List[List[str]]:
    """
    Create properly aligned rows for a function's artifacts with tree structure.
    Each artifact is colored based on its type (API, string, CAPA, etc.)

    Args:
        func_ea: Function effective address
        artifacts: List of artifacts (type_id, content) tuples
        xrefer_obj: XRefer instance for color tag lookup

    Returns:
        List of formatted rows with proper tree structure and alignment
    """
    rows = []
    first_artifact = artifacts[0]

    # Get current address string
    addr_str = f"0x{func_ea:x}"

    # Fixed components
    arrow_str = "◄───────┐"
    min_padding = 2  # Minimum spaces between address and arrow

    # Calculate total width based on address length
    total_width = len(addr_str) + min_padding + len(arrow_str)

    # Create first row
    colored_addr = f"\x01{ida_lines.SCOLOR_CREFTAIL}{addr_str}\x02{ida_lines.SCOLOR_CREFTAIL}"
    colored_arrow = f"{' ' * min_padding}\x01{ida_lines.SCOLOR_LIBNAME}{arrow_str}\x02{ida_lines.SCOLOR_LIBNAME}"

    # Color first artifact based on its type
    artifact_color = xrefer_obj.color_tags[xrefer_obj.table_names[first_artifact[0]]]
    colored_artifact = f"\x01{artifact_color}{first_artifact[1]}\x02{artifact_color}"
    colored_func_name = f"\x01{ida_lines.SCOLOR_DEMNAME}{idc.get_func_name(func_ea)}\x02{ida_lines.SCOLOR_DEMNAME}"

    first_row = [f"{colored_addr}{colored_arrow}", f" {colored_artifact}", colored_func_name]
    rows.append(first_row)

    # Calculate dynamic vertical indent to align with the end of arrow
    vertical_indent = " " * (total_width - 1)  # -1 to align with the vertical part of ┐

    # Process remaining artifacts
    seen_artifacts = {(first_artifact[0], first_artifact[1])}  # Track seen artifacts by type and content

    for artifact in artifacts[1:]:
        # Skip if we've already seen this artifact
        if (artifact[0], artifact[1]) in seen_artifacts:
            continue

        seen_artifacts.add((artifact[0], artifact[1]))

        # Color artifact based on its type
        artifact_color = xrefer_obj.color_tags[xrefer_obj.table_names[artifact[0]]]
        colored_artifact = f"\x01{artifact_color}{artifact[1]}\x02{artifact_color}"

        # Last connector should be └, others should be │
        connector = "└" if len(seen_artifacts) == len(artifacts) else "│"
        connector = f"{vertical_indent}\x01{ida_lines.SCOLOR_LIBNAME}{connector}\x02{ida_lines.SCOLOR_LIBNAME}"

        row = [connector, f" {colored_artifact}", ""]
        rows.append(row)

    return rows


def prepare_interesting_artifacts_table_rows(func_artifacts_dict, xrefer_obj):
    """
    Prepare complete table rows with proper spacing between function groups.

    Args:
        func_artifacts_dict: Dictionary of functions and their artifacts
        xrefer_obj: XRefer instance for color tags

    Returns:
        List of formatted and aligned table rows
    """
    rows = []

    # Create a map of unique artifact sets for each function
    unique_artifacts = {}
    for func_ea, artifacts in func_artifacts_dict.items():
        # Use tuple of (type_id, content) as key for uniqueness
        unique_set = []
        seen = set()
        for artifact in artifacts:
            key = (artifact[0], artifact[1])
            if key not in seen:
                seen.add(key)
                unique_set.append(artifact)
        unique_artifacts[func_ea] = unique_set

    # Sort functions by number of unique artifacts
    sorted_funcs = sorted(unique_artifacts.items(), key=lambda x: len(x[1]), reverse=True)

    # Generate rows for each function
    for i, (func_ea, unique_artifact_list) in enumerate(sorted_funcs):
        func_rows = create_function_rows_for_interesting_artifacts(func_ea, unique_artifact_list, xrefer_obj)
        rows.extend(func_rows)

        # Add separator between functions, except for the last one
        if i < len(sorted_funcs) - 1:
            rows.append(["", "", ""])  # Empty row for spacing

    return rows


def create_interesting_artifacts_table(headings, rows, color):
    """
    Create complete table with headers and content, maintaining alignment.

    Handles:
    - Header formatting with proper column widths
    - Separator lines under headers
    - Content alignment accounting for color codes
    - Consistent spacing between columns
    - Proper indentation throughout table

    Uses color-aware width calculations to ensure alignment remains consistent
    regardless of different color codes used for different types of artifacts.

    Args:
        headings: List of column headers
        rows: List of data rows
        color: IDA color code for headers

    Returns:
        List of formatted table lines with proper alignment
    """
    col_widths = [0] * len(headings)

    # Include headers in width calculations
    for i, heading in enumerate(headings):
        col_widths[i] = len(heading)

    # Calculate widths from data rows
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], get_visible_width(cell))

    # Add padding between columns
    col_widths = [w + 2 for w in col_widths]

    # Format headers
    formatted_rows = []
    header_row = []
    for i, heading in enumerate(headings):
        padding = " " * (col_widths[i] - len(heading))
        header_row.append(f"\x01{color}{heading}{padding}\x02{color}")
    formatted_rows.append("".join(header_row))

    # Add header separator
    separator_row = []
    for width in col_widths:
        separator_row.append(f"\x01{color}{'-' * (width - 1)}\x02{color} ")
    formatted_rows.append("".join(separator_row))

    # Add empty line after header
    formatted_rows.append("")

    # Format data rows
    for row in rows:
        formatted_cells = []
        for i, cell in enumerate(row):
            if i < len(col_widths):
                visible_length = get_visible_width(cell)
                padding = " " * (col_widths[i] - visible_length)
                formatted_cells.append(f"{cell}{padding}")
        formatted_rows.append("".join(formatted_cells))

    formatted_rows.append("")
    formatted_rows.append("".join(separator_row))
    return formatted_rows


def create_cluster_relationship_graph(clusters: List["FunctionalCluster"], analysis: Dict) -> Optional[nx.DiGraph]:
    """Create graph respecting merge hierarchy and hiding merged nodes."""
    if not clusters:
        return None

    try:
        graph = nx.DiGraph()

        # Track nodes and merged states
        added_nodes = set()
        merged_nodes = {}  # Maps merged_id -> parent_id

        def add_valid_node(node_id: str, label: str = "") -> bool:
            """Add node with validation of merge state."""
            if not isinstance(node_id, str) or not node_id.strip():
                return False

            # Check if this is a merged node
            try:
                cluster_id = int(node_id.split(".")[-1])
                if cluster_id in merged_nodes:
                    # Don't add individual merged nodes
                    return False
            except (ValueError, IndexError):
                pass

            node_text = f"{node_id}\n{label}" if label else node_id
            if len(node_text) > 500:  # Reasonable limit
                node_text = node_text[:497] + "..."

            if node_text not in added_nodes:
                graph.add_node(node_text)
                added_nodes.add(node_text)
            return True

        def add_valid_edge(source: str, target: str) -> bool:
            """Add edge respecting merge hierarchy."""
            if source not in added_nodes or target not in added_nodes:
                return False
            if source == target:
                return False

            # Extract cluster IDs
            try:
                source_id = int(source.split(".")[-1])
                target_id = int(target.split(".")[-1])

                # If either node is merged, remap to parent
                if source_id in merged_nodes:
                    source_text = f"cluster.id.{merged_nodes[source_id]}"
                    if source_text not in added_nodes:
                        return False
                    source = source_text
                if target_id in merged_nodes:
                    target_text = f"cluster.id.{merged_nodes[target_id]}"
                    if target_text not in added_nodes:
                        return False
                    target = target_text
            except (ValueError, IndexError):
                pass

            graph.add_edge(source, target)
            return True

        # Process multiple clusters case
        for cluster in clusters:
            cluster_id = f"cluster.id.{cluster.id:04d}"
            if cluster.id in merged_nodes:
                continue  # Skip merged nodes

            # Get cluster data
            cluster_data = find_cluster_analysis(analysis, cluster.id)
            if not cluster_data:
                continue

            label = cluster_data.get("label", "").strip()
            if not add_valid_node(cluster_id, label):
                continue

            node_text = f"{cluster_id}\n{label}" if label else cluster_id

            # Process relationships respecting merges
            if cluster.parent_cluster_id:
                parent_data = find_cluster_analysis(analysis, cluster.parent_cluster_id)
                if parent_data:
                    parent_id = f"cluster.id.{cluster.parent_cluster_id:04d}"
                    parent_label = parent_data.get("label", "").strip()
                    if add_valid_node(parent_id, parent_label):
                        parent_text = f"{parent_id}\n{parent_label}" if parent_label else parent_id
                        add_valid_edge(parent_text, node_text)

            # Handle subclusters
            for subcluster in cluster.subclusters:
                sub_data = find_cluster_analysis(analysis, subcluster.id)
                if sub_data and subcluster.id not in merged_nodes:
                    sub_id = f"cluster.id.{subcluster.id:04d}"
                    sub_label = sub_data.get("label", "").strip()
                    if add_valid_node(sub_id, sub_label):
                        sub_text = f"{sub_id}\n{sub_label}" if sub_label else sub_id
                        add_valid_edge(node_text, sub_text)

            # Handle cluster references
            for _, ref_id in cluster.cluster_refs.items():
                if ref_id not in merged_nodes:  # Skip refs to merged nodes
                    ref_data = find_cluster_analysis(analysis, ref_id)
                    if ref_data:
                        ref_id_str = f"cluster.id.{ref_id:04d}"
                        ref_label = ref_data.get("label", "").strip()
                        if add_valid_node(ref_id_str, ref_label):
                            ref_text = f"{ref_id_str}\n{ref_label}" if ref_label else ref_id_str
                            add_valid_edge(node_text, ref_text)

        return graph

    except Exception as e:
        log(f"Error creating relationship graph: {str(e)}")
        return None


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


def create_cluster_table(headings: List[str], rows: List[List[Any]], color: int) -> List[str]:
    """
    Create formatted table for clusters with consistent alignment.
    Similar to create_interesting_artifacts_table but specialized for cluster format.
    """
    # Calculate max widths for each column
    col_widths = [len(h) for h in headings]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], get_visible_width(cell))

    # Add padding
    col_widths = [w + 2 for w in col_widths]

    # Format header
    formatted_rows = []
    header_row = []
    for i, heading in enumerate(headings):
        padding = " " * (col_widths[i] - len(heading))
        header_row.append(f"{heading}{padding}")
    formatted_rows.append(ida_lines.COLSTR("".join(header_row), color))

    # Add separator
    separator = []
    for width in col_widths:
        separator.append("-" * (width - 1) + " ")
    formatted_rows.append(ida_lines.COLSTR("".join(separator), color))
    formatted_rows.append("")  # Empty line after header

    # Format data rows with proper alignment
    for row in rows:
        formatted_row = []
        for i, cell in enumerate(row):
            if cell:  # Only add padding if cell has content
                # Color cluster IDs consistently
                cell = re.sub(r"(cluster\.id\.\d{4})", lambda m: f"\x01{ida_lines.SCOLOR_DATNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DATNAME}", cell)
                visible_length = get_visible_width(cell)
                padding = " " * (col_widths[i] - visible_length)
                formatted_row.append(f"{cell}{padding}")
        formatted_rows.append("".join(formatted_row))

    return formatted_rows


def calculate_first_column_width(clusters, analysis_data):
    """Calculate required width for first column based on longest cluster label."""
    max_width = 0

    def check_cluster(cluster):
        nonlocal max_width
        # Get cluster label from analysis data
        cluster_label = ""
        cluster_analysis_data = find_cluster_analysis(analysis_data, cluster.id)
        if cluster_analysis_data:
            cluster_label = cluster_analysis_data.get("label", "")

        cluster_str = f"[{cluster.id}] {cluster_label}"
        max_width = max(max_width, len(cluster_str))
        for subcluster in cluster.subclusters:
            check_cluster(subcluster)

    if isinstance(clusters, list):
        for cluster in clusters:
            check_cluster(cluster)
    else:
        check_cluster(clusters)

    # Add some padding for arrow head and corner
    return max_width + 15  # minimum space for arrow


def create_cluster_rows(cluster, analysis, column_width, paths):
    """
    Create properly aligned rows for a cluster with visual indicators for entry points.
    Dynamically arranges description and function list in parallel, with properly colored separator.

    Args:
        cluster: FunctionalCluster object
        analysis: Dictionary containing analysis for this cluster
        column_width: Width for consistent alignment
        paths: Dictionary of paths to check for entry points

    Returns:
        List[List[str]]: Formatted rows for display
    """
    rows = []

    # Get cluster info
    cluster_id = cluster.id_str
    cluster_label = ""
    description = ""
    relationships = ""

    # Extract data from analysis if available
    cluster_analysis_data = find_cluster_analysis(analysis, cluster.id)
    if cluster_analysis_data:
        cluster_label = cluster_analysis_data.get("label", "")
        description = cluster_analysis_data.get("description", "")
        relationships = cluster_analysis_data.get("relationships", "")

    # Add entry point indicator if applicable
    entry_point_indicator = ""
    if any(ep in cluster.nodes for ep in paths):
        entry_point_indicator = " ★"  # Star indicator for entry point clusters

    # Format cluster identifier with colors
    cluster_str = f"] {cluster_label}{entry_point_indicator}"
    cluster_id_str = f"{cluster_id}"
    cluster_colored = f"\x01{ida_lines.SCOLOR_DEMNAME}[\x01\x18{cluster_id_str}\x02\x18{cluster_str}\x02{ida_lines.SCOLOR_DEMNAME}"

    # Calculate arrow components
    base_padding = 2
    remaining_space = column_width - len(cluster_str + cluster_id_str) - base_padding - 1
    arrow_line = "─" * (remaining_space - 2)
    arrow_str = f"{' ' * base_padding}◄{arrow_line}┐"
    arrow = f"\x01{ida_lines.SCOLOR_LIBNAME}{arrow_str}\x02{ida_lines.SCOLOR_LIBNAME}"

    # Calculate vertical line position
    vert_line_pos = column_width - 1

    # Process nodes and description
    nodes = sorted(cluster.nodes)
    if nodes:
        # First row with cluster info and first node
        first_node = nodes[0]
        func_name = idc.get_func_name(first_node)
        if len(func_name) > 13:
            func_name = f"{func_name[:11]}.."
        func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
        node_str = f"0x{first_node:x} \x01\x18->\x02\x18 {func_name}"
        node_colored = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"

        # Add first row
        rows.append([f"{cluster_colored}{arrow}", node_colored])

        # Get the remaining nodes
        remaining_nodes = nodes[1:]

        # Add separator line if we have a description
        if description:
            separator = "─" * (column_width - 2) + " "  # -2 for space and vertical line
            vert_line = f"\x01{ida_lines.SCOLOR_LIBNAME}│\x02{ida_lines.SCOLOR_LIBNAME}"

            # If we have more nodes, show the next node with the separator line
            if remaining_nodes:
                node = remaining_nodes[0]
                func_name = idc.get_func_name(node)
                if len(func_name) > 13:
                    func_name = f"{func_name[:11]}.."
                func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
                node_str = f"0x{node:x} \x01\x18->\x02\x18 {func_name}"
                node_colored = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"
                remaining_nodes = remaining_nodes[1:]  # Remove the used node
            else:
                node_colored = ""

            rows.append([f"\x01{ida_lines.SCOLOR_DEMNAME}{separator}\x02{ida_lines.SCOLOR_DEMNAME}{vert_line}", node_colored])

        # Prepare description lines
        desc_lines = []
        if description or relationships:
            full_desc = f"{description} {relationships}"
            desc_width = column_width - 2
            desc_lines = word_wrap_text(full_desc, desc_width)

        # Create rows combining description and nodes
        max_rows = max(len(desc_lines), len(remaining_nodes))
        for i in range(max_rows):
            # Determine if this is the last content line
            is_last_line = i == max_rows - 1

            # Prepare left column (description)
            if i < len(desc_lines):
                desc_line = desc_lines[i]
                desc_colored = f"\x01{ida_lines.SCOLOR_DSTR}{desc_line}\x02{ida_lines.SCOLOR_DSTR}"
                padding_needed = column_width - len(desc_line)
                padding = " " * (padding_needed - 1)
                connector = "└" if is_last_line else "│"
                vert_line = f"\x01{ida_lines.SCOLOR_LIBNAME}{connector}\x02{ida_lines.SCOLOR_LIBNAME}"
                left_col = f"{desc_colored}{padding}{vert_line}"
            else:
                # Just the vertical line with proper spacing if no more description
                connector = "└" if is_last_line else "│"
                left_col = f"{' ' * (vert_line_pos)}\x01{ida_lines.SCOLOR_LIBNAME}{connector}\x02{ida_lines.SCOLOR_LIBNAME}"

            # Prepare right column (function)
            right_col = ""
            if i < len(remaining_nodes):
                node = remaining_nodes[i]
                func_name = idc.get_func_name(node)
                if len(func_name) > 13:
                    func_name = f"{func_name[:11]}.."
                func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
                node_str = f"0x{node:x} \x01\x18->\x02\x18 {func_name}"
                right_col = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"

            rows.append([left_col, right_col])

    # Add subclusters
    for subcluster in cluster.subclusters:
        # Add exactly one empty row before each subcluster
        rows.append(["", ""])

        sub_rows = create_cluster_rows(subcluster, analysis, column_width, paths)
        # Remove the trailing empty row that comes with sub_rows to avoid accumulation
        if sub_rows and not sub_rows[-1][0] and not sub_rows[-1][1]:
            sub_rows.pop()
        rows.extend(sub_rows)

    # Always add exactly one empty row after the cluster
    rows.append(["", ""])
    return rows


def draw_cluster_hierarchy(clusters, analysis, paths):
    """
    Draw all clusters in a hierarchical table format with proper sorting.

    Args:
        clusters: List of clusters to display
        analysis: Dictionary containing analysis data for clusters
        paths: Dictionary of paths to check for entry points

    Returns:
        List[str]: Formatted lines ready for display
    """
    if not clusters:
        return ["    NO CLUSTERS TO DISPLAY"]

    # Sort clusters
    sorted_clusters = sort_clusters(clusters, paths)

    # Add main heading
    lines = []

    # Calculate required column width based on all clusters
    column_width = calculate_first_column_width(sorted_clusters, analysis)

    # Prepare all rows including subclusters
    all_rows = []
    first_non_ep_cluster = True

    # Process each cluster
    for cluster in sorted_clusters:
        # Add separator before first non-entry point cluster
        if first_non_ep_cluster and cluster.parent_cluster_id is None and not any(ep in cluster.nodes for ep in paths):
            first_non_ep_cluster = False

        cluster_rows = create_cluster_rows(cluster, analysis, column_width, paths)
        all_rows.extend(cluster_rows)

        # Add spacing between primary clusters
        if cluster.parent_cluster_id is None:
            all_rows.append(["", ""])

    if not all_rows:
        return ["    NO CLUSTERS TO DISPLAY"]

    # Create table
    headings = ["Cluster", "Node"]
    table = create_cluster_table(headings, all_rows, ida_lines.SCOLOR_DATNAME)

    # Format lines with proper indentation
    formatted_lines = []
    for line in table:
        if line.strip():
            formatted_lines.append(f"    {line}")
        else:
            formatted_lines.append("")

    return formatted_lines


def sort_clusters(clusters, paths):
    """
    Sort clusters based on entry point reachability and parent/child relationships.

    Args:
        clusters: List of FunctionalCluster objects
        xrefer_obj: XRefer instance containing entry point information

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


def is_call_insn(addr: int) -> bool:
    """
    Check if the instruction at the given address is a call instruction.

    Args:
        addr (int): The address to check.

    Returns:
        bool: True if the instruction is a call, False otherwise.
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, addr) and ida_idp.is_call_insn(insn):
        return True
    return False


def set_focus_to_code(pseudo: bool = True) -> None:
    """
    Set focus to the code or pseudocode window in IDA.

    Args:
        pseudo (bool): If True, focus on pseudocode, otherwise on disassembly.
    """
    widget_prefix = "Pseudocode-" if pseudo else "IDA View-"

    for i in range(ord("A"), ord("Z") + 1):
        disassembly_title = f"{widget_prefix}{chr(i)}"
        widget = ida_kernwin.find_widget(disassembly_title)
        if widget:
            ida_kernwin.activate_widget(widget, True)
            break


def navigate_back() -> None:
    """
    Navigate back in IDA's navigation history.
    """
    action_name = "JumpPrev"
    ida_kernwin.process_ui_action(action_name)


def register_menu_action(menu_path: str, menu_id: str, label: str, handler: idaapi.action_handler_t) -> None:
    """
    Register a menu action in IDA.

    Creates and registers an action in IDA's menu system with given handler.

    Args:
        menu_path (str): Path in menu where action should appear
        menu_id (str): Unique identifier for the action
        label (str): Display label for the menu item
        handler (idaapi.action_handler_t): Handler class for the action
    """
    action_desc = idaapi.action_desc_t(menu_id, label, handler, None, label)
    idaapi.register_action(action_desc)
    idaapi.attach_action_to_menu(menu_path, menu_id, idaapi.SETMENU_APP)


def register_popup_action(form: Any, popup: Any, menu_path: str, menu_id: str, label: str, handler: idaapi.action_handler_t, tooltip: str) -> None:
    """
    Register a popup menu action in IDA.

    Creates and registers an action in IDA's popup menu system.

    Args:
        form: Form widget containing popup menu
        popup: Popup menu instance
        menu_path (str): Path in menu where action should appear
        menu_id (str): Unique identifier for the action
        label (str): Display label for the menu item
        handler (idaapi.action_handler_t): Handler class for the action
        tooltip (str): Tooltip text for the menu item
    """
    action = idaapi.action_desc_t(menu_id, label, handler, None, tooltip, -1)
    idaapi.register_action(action)
    idaapi.attach_action_to_popup(form, popup, menu_id, menu_path)


def is_windows_or_linux() -> bool:
    """
    Check if current platform is Windows or Linux.

    Used for platform-specific UI adjustments.

    Returns:
        bool: True if platform is Windows or Linux
    """
    _platform = platform.system().lower()
    return _platform in ("windows", "linux")


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


def remove_non_displayable(s: str) -> str:
    """
    Remove non-displayable characters from string.

    Args:
        s (str): Input string containing potential non-displayable characters

    Returns:
        str: String with non-displayable characters removed
    """
    return "".join(c for c in s if unicodedata.category(c)[0] != "C")


def is_mac_dark_mode_enabled() -> bool:
    """
    Check if dark mode is enabled on macOS.

    Returns:
        bool: True if dark mode is enabled, False otherwise.
    """
    mode = os.popen("defaults read -g AppleInterfaceStyle 2>/dev/null").read().strip()
    return mode == "Dark"


def is_ida_default_light_theme_enabled() -> Optional[bool]:
    """
    Check if the default light theme is enabled in IDA Pro on macOS.

    Returns:
        Optional[bool]: True if the default light theme is enabled, False if dark mode is enabled, None for other cases.
    """
    system_name = platform.system()
    theme_string = ida_registry.reg_read_string("ThemeName")
    default_theme_values = ("", "default", None)

    if system_name == "Darwin":
        if theme_string in default_theme_values:
            if is_mac_dark_mode_enabled():
                return False
            else:
                return True
    return None


def get_segment_by_name(segment_name: str) -> Optional[ida_segment.segment_t]:
    """
    Get IDA segment object by its name.

    Case-insensitive search for segment with specified name.

    Args:
        segment_name (str): Name of segment to find

    Returns:
        Optional[ida_segment.segment_t]: Segment object if found, None otherwise
    """
    curr = ida_segment.get_first_seg()
    last = ida_segment.get_last_seg()

    while curr.start_ea != last.start_ea:
        if ida_segment.get_segm_name(curr).lower() == segment_name.lower():
            return curr
        curr = ida_segment.get_next_seg(curr.start_ea)
    return None


def make_string(ea: int, size: int, undefine_first: bool = True) -> bool:
    """
    Create a string at specified address.

    Optionally undefines existing data before creating string.

    Args:
        ea (int): Address to create string at
        size (int): Size of string in bytes
        undefine_first (bool): Whether to undefine existing data first

    Returns:
        bool: True if string was created successfully
    """
    if undefine_first:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    return ida_bytes.create_strlit(ea, size, ida_nalt.STRTYPE_TERMCHR)


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


def patch_asciinet() -> None:
    """
    Patch asciinet library for proper UTF-8 handling.

    Wraps original asciinet functions to ensure proper encoding/decoding
    of graph output for IDA's text display.
    """
    original_graph_to_ascii = asciinet.graph_to_ascii
    original_AsciiGraphProxy_graph_to_ascii = asciinet._AsciiGraphProxy.graph_to_ascii

    @wraps(original_graph_to_ascii)
    def patched_graph_to_ascii(graph, timeout=10):
        result = original_graph_to_ascii(graph, timeout)
        if isinstance(result, bytes):
            return result.decode(encoding="UTF-8")
        return result

    @wraps(original_AsciiGraphProxy_graph_to_ascii)
    def patched_AsciiGraphProxy_graph_to_ascii(self, graph, timeout=10):
        result = original_AsciiGraphProxy_graph_to_ascii(self, graph, timeout)
        if isinstance(result, bytes):
            return result
        elif isinstance(result, str):
            return result.encode("UTF-8")
        else:
            raise TypeError(f"Unexpected type returned: {type(result)}")

    asciinet.graph_to_ascii = patched_graph_to_ascii
    asciinet._AsciiGraphProxy.graph_to_ascii = patched_AsciiGraphProxy_graph_to_ascii


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


def help_text() -> List[str]:
    """
    Generate complete help text for XRefer.

    Creates formatted help text explaining all available commands,
    keyboard shortcuts, and features of XRefer.

    Returns:
        List[str]: List of lines containing formatted help text
    """
    help_text = """
 ------------------------------------------------------------------------------------------
  /$$   /$$ /$$$$$$$             /$$$$$$
 | $$  / $$| $$__  $$           /$$__  $$
 |  $$/ $$/| $$  \ $$  /$$$$$$ | $$  \__//$$$$$$   /$$$$$$
  \  $$$$/ | $$$$$$$/ /$$__  $$| $$$$   /$$__  $$ /$$__  $$
   >$$  $$ | $$__  $$| $$$$$$$$| $$_/  | $$$$$$$$| $$  \__/
  /$$/\  $$| $$  \ $$| $$_____/| $$    | $$_____/| $$
 | $$  \ $$| $$  | $$|  $$$$$$$| $$    |  $$$$$$$| $$
 |__/  |__/|__/  |__/ \_______/|__/     \_______/|__/

                The Binary Navigator (XRefer) - Help
 ------------------------------------------------------------------------------------------

 KEYS AVAILABLE IN ALL MODES:
 [ESC]      Return to previous state or switch focus back to IDA code view
 [ENTER]    Return to home view
 [H]        Show/hide this help
 [D]        Add selected artifacts (APIs/libs/strings/CAPA) to exclusions
 [U]        Toggle exclusions globally
 [E]        Expand or collapse current table sections
 (MOUSE)    Click/double-click/hover items or nodes to interact, select artifacts, show details

 ----------------------------------------

 HOME VIEW (initial state):
 [S]    Enter search mode to filter the current display by typing text
 [T]    Enter trace mode; press repeatedly to cycle through function/path/full API call scopes
 [C]    Show clusters; press again to toggle between cluster table and cluster relationship graph
 [I]    Show interesting artifacts identified by analysis
 [X]    When on an artifact, show its cross-references listing
 [B]    With artifacts selected, find boundary methods that contain all selected items
 [L]    Show last boundary scan results

 ----------------------------------------

 SEARCH MODE:
 Type to filter the current content
 [ESC/ENTER] Exit search mode and return to home view

 ----------------------------------------

 TRACE SCOPES (after pressing [T] in home view):
 Press [T] repeatedly to cycle:
  - Function scope: API calls in current function
  - Path scope: Calls along paths to this function
  - Full scope: All recorded calls in trace
 [ESC/ENTER] Return to home view

 ----------------------------------------

 CLUSTERS & CLUSTER GRAPHS (after pressing [C] in home view):
 [C]    Switch between cluster table and cluster relationship graph view
 [J]    Enable/disable cluster sync with navigation
 [ESC/ENTER] Return to home view

 ----------------------------------------

 GRAPH VIEWS (after pressing [G] on an artifact in home view):
 [G]    Show path graph to artifact; press again to pin/unpin the graph
 [S]    Toggle simplified/normal graph representation
 (MOUSE) Hover/click/dbl-click nodes for details or navigation
 [ESC/ENTER] Return to home view

 ----------------------------------------

 INTERESTING ARTIFACTS (after pressing [I] in home view):
 [ESC/ENTER] Return to home view

 ----------------------------------------

 XREF LISTING (after pressing [X] on artifact in home view):
 [ESC/ENTER] Return to home view

 ----------------------------------------

 BOUNDARY SCANS (after pressing [B] with artifacts selected in home view):
 [L]    Show results of the last boundary scan
 [ESC/ENTER] Return to home view

 ----------------------------------------

 MOUSE INTERACTIONS:
  - Click items to expand or access sub-details
  - Double-click artifacts to select them for operations
  - Hover over items or graph nodes for tooltips and context

 ----------------------------------------

 TIPS & NOTES:
  - Pressing [ESC] multiple times often steps you back to home view
  - Some keys like [T], [C], [G], [I] cycle through related modes each press
  - Selected artifacts remain chosen until toggled off by double-clicking them again
  - Use exclusions ([D], [U]) to refine displayed artifacts
  - Experiment with cluster graphs, traces, and paths for deeper insight

 ----------------------------------------

 Press [H] to hide this help.
 """
    return help_text.splitlines()
