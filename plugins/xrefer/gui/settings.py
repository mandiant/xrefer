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

import copy
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

from qtpy.QtCore import Qt
from qtpy.QtGui import QColor, QFont, QFontMetrics, QPalette
from qtpy.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                            QMessageBox, QPushButton, QScrollArea, QSizePolicy, QSpinBox, QStackedWidget, QVBoxLayout, QWidget)

from xrefer.core.settings import XReferSettingsManager

if TYPE_CHECKING:
    from xrefer.core.settings import ExclusionData

# Constants
# Default dialog size — 1080x720 fits the General tab's Options +
# Display Options + Paths cards without scrolling on default IDA
# font sizes. Min size lets cramped displays still open the dialog;
# the QScrollArea around each page handles overflow.
DIALOG_WIDTH = 1080
# 760 (bumped from 720) clears the few-pixel content overflow that
# made the scrollbar appear despite there being nothing meaningful
# to scroll to. Keeps the resizable behavior intact — users on
# smaller screens still hit setMinimumSize below.
DIALOG_HEIGHT = 760
DIALOG_MIN_WIDTH = 900
DIALOG_MIN_HEIGHT = 540
SIDEBAR_WIDTH = 180
BUTTON_SIZE = 24
MAX_WILDCARD_MATCHES = 10

# File filter constants
FILE_FILTERS = {
    "trace": "Zip Files (*.zip);;JSON Files (*.json);;Tag Files (*.tag);;All Files (*.*)",
    "capa": "JSON Files (*.json);;All Files (*.*)",
    "analysis": "XRefer Files (*.xrefer);;All Files (*.*)",
    "exclusions": "JSON Files (*.json);;All Files (*.*)",
    "default": "All Files (*.*)",
}


# Compatibility criteria for the LLM model dropdown. A model is shown only if
# it satisfies ALL of:
#   - chat-completion API (DSPy uses chat endpoints)
#   - >=200k input tokens — a COARSE pre-filter only: it keeps tiny-context
#     models (8k/32k/128k) out of the list, since cluster prompts get large on
#     real binaries. It does NOT prove a given binary fits; that's decided per
#     binary at analysis time by the token-budget gate, which renders the real
#     request, compares it to the model's context window, and refuses to send
#     when it would overflow (XRefer.analyze_clusters /
#     ClusterAnalyzer.estimate_cluster_request).
#   - >=16k output tokens (matches the codebase's per-provider max_tokens floor)
#   - structured output capability (DSPy Predict + Pydantic OutputField needs
#     either JSON-schema response_format or function-calling fallback)
#   - single-API-key auth: xrefer collects exactly ONE api_key and calls
#     dspy.LM(model, api_key), so litellm.validate_environment(model, api_key)
#     must report nothing else missing. This is the *real* reason AWS-Bedrock,
#     Azure and Vertex models are out — they need access keys / endpoints / GCP
#     projects xrefer has no field for, not a lone api_key.
# The provider allowlist is the first cut: it keeps the dropdown free of the
# 100+ gateway/reseller duplicates (OpenRouter / Vercel / deepinfra / etc.) that
# merely re-list the same models, and of a few providers litellm reports as
# single-key when they really need a host/endpoint (azure_ai / oci / databricks).
# validate_environment (in _curated_llm_models) is the enforced auth gate on top.
# Anthropic is included: standard Claude reports a 200k window and now qualifies
# directly. Claude's larger 1M window is beta-gated (needs the
# anthropic-beta:context-1m-2025-08-07 header AND API tier 4+); xrefer sends that
# header automatically for >=1M Claude ids from the LLM call path
# (LLMProcessor._build_lm_kwargs), so the wider window holds at runtime where
# offered. Tier 4+ stays the user's responsibility.
# dashscope (Alibaba Qwen) is the one non-big-4 direct single-key provider with
# qualifying structured-output models, so it's allowed too.
_LLM_MIN_INPUT_TOKENS = 200_000
_LLM_MIN_OUTPUT_TOKENS = 16_000
_LLM_ALLOWED_PROVIDERS = frozenset({"openai", "gemini", "xai", "anthropic", "dashscope"})


def _curated_llm_models() -> List[str]:
    """Return models from litellm.model_cost that meet XRefer's workload requirements.

    Returns an empty list if litellm is unavailable — the caller renders an empty
    dropdown, which is the right signal since processor.py also imports litellm.
    """
    try:
        import litellm
        cost_table = litellm.model_cost
    except (ImportError, AttributeError):
        return []

    seen: set = set()
    out: List[str] = []
    for name, info in cost_table.items():
        if not isinstance(info, dict):
            continue
        if info.get("mode") != "chat":
            continue
        provider = info.get("litellm_provider")
        if provider not in _LLM_ALLOWED_PROVIDERS:
            continue
        try:
            max_in = int(info.get("max_input_tokens") or 0)
            max_out = int(info.get("max_output_tokens") or 0)
        except (TypeError, ValueError):
            continue
        if max_in < _LLM_MIN_INPUT_TOKENS or max_out < _LLM_MIN_OUTPUT_TOKENS:
            continue
        if not (info.get("supports_response_schema") or info.get("supports_function_calling")):
            continue
        if name.startswith("ft:"):  # fine-tuned templates, not callable model ids
            continue
        if "/" not in name:  # normalize bare names to provider/model form
            name = f"{provider}/{name}"
        # Hard single-API-key gate (see criteria comment above). xrefer has
        # exactly one api_key field, so a model is only usable if a lone
        # api_key leaves validate_environment with nothing missing. Runs last
        # — it's the most expensive check, so only already-filtered candidates
        # reach it. The placeholder key stands in for "the key the user will
        # supply"; we only care whether ONE key is sufficient, not its value.
        try:
            env = litellm.validate_environment(model=name, api_key="xrefer-probe-key")
            if not env.get("keys_in_environment"):
                continue
        except Exception:
            continue
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return sorted(out)


def make_combo_searchable(combo) -> None:
    """Give a QComboBox type-to-filter search over its items — handy for the
    long curated-model list. Matches a typed substring anywhere in the item
    (so "opus" finds "anthropic/claude-opus-4-5"), case-insensitively.

    Leaves the combo editable with NoInsert, so a custom hand-typed model id
    still works (typing only filters the list, never adds an item). Configures
    the auto-created completer and is safe to call on an already-editable combo
    — it won't recreate the line edit (which would drop existing handlers).
    """
    from qtpy.QtCore import Qt
    from qtpy.QtWidgets import QComboBox, QCompleter

    if not combo.isEditable():
        combo.setEditable(True)
    combo.setInsertPolicy(QComboBox.NoInsert)
    completer = combo.completer()
    if completer is not None:
        completer.setCompletionMode(QCompleter.PopupCompletion)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        try:
            completer.setFilterMode(Qt.MatchContains)
        except Exception:
            pass  # older Qt without setFilterMode keeps prefix matching
        # Style the filter popup to match the dialog: theme-aware via QSS
        # palette() roles (same approach as _build_dialog_qss), with an accent
        # selection highlight and a little padding so it reads as "sleek"
        # rather than the raw native list.
        popup = completer.popup()
        if popup is not None:
            popup.setStyleSheet(
                "QAbstractItemView {"
                " background: palette(base); color: palette(text);"
                " border: 1px solid palette(mid); outline: 0; padding: 3px; }"
                "QAbstractItemView::item { padding: 5px 8px; border-radius: 4px; }"
                "QAbstractItemView::item:selected {"
                " background: palette(highlight); color: palette(highlighted-text); }"
            )


# Per-process scratch directory for the small SVG icon files referenced
# by ``_build_dialog_qss`` in QSS ``image:`` rules. We don't ship the
# icons as static assets because their stroke color is computed from
# the active IDA palette — embedding the color inline (one SVG file
# per dialog open) is simpler than maintaining N pre-rendered palette
# variants. The OS cleans the dir up on process exit; we keep a single
# stable path per process so repeated dialog opens reuse the same
# files instead of accumulating directories.
_ICON_CACHE_DIR = Path(tempfile.gettempdir()) / f"xrefer_settings_icons_{os.getpid()}"


def _write_icon_cache(contents: Dict[str, str]) -> Dict[str, str]:
    """Write a name→SVG-content map to the icon cache dir, returning
    a name→path map for use in QSS ``image:`` properties.

    Qt's QSS ``url(...)`` resolver does NOT handle ``file://`` URIs
    correctly — it strips the scheme prefix incorrectly and ends up
    interpreting the residual as a CWD-relative path. The fix is to
    pass a plain absolute path with forward-slash separators (the
    latter for Windows: backslashes confuse the QSS parser). Qt
    accepts both POSIX and Windows-drive-letter absolute paths in
    this form.
    """
    _ICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    urls: Dict[str, str] = {}
    for name, svg in contents.items():
        path = _ICON_CACHE_DIR / name
        path.write_text(svg)
        # Forward slashes are mandatory in QSS url() on Windows; on
        # POSIX they're already correct. str(path) gives the platform
        # separator, so normalize explicitly.
        urls[name] = str(path).replace("\\", "/")
    return urls


def _build_dialog_qss() -> str:
    """Compose the settings-dialog stylesheet from the active Qt palette.

    Accent color is taken from ``QPalette.Highlight`` so the dialog
    blends with whatever IDA theme the user runs (dark or light, with
    whatever selection color they've configured). Card / input / border
    backgrounds are derived by shading the palette ``Window`` color —
    on dark themes we lighten, on light themes we darken — so the
    derived colors stay close to the host theme without us hard-coding
    a palette of our own.

    The result is applied via ``self.setStyleSheet(...)`` on the
    settings dialog: QSS scopes to descendants of the widget it's set
    on, so this affects only the settings dialog (not other IDA
    surfaces or other xrefer dialogs).

    Cross-platform note: once a widget has a stylesheet, Qt paints it
    non-natively, which is what we want here — the macOS / Windows /
    Linux native paint paths each had visual issues (invisible tab
    selection on macOS dark mode being the worst), so painting via QSS
    is the consistency mechanism.
    """
    palette = QApplication.palette()
    window = palette.color(QPalette.Window)
    text = palette.color(QPalette.WindowText)
    is_dark = window.lightnessF() < 0.5

    accent = palette.color(QPalette.Highlight)
    accent_text = palette.color(QPalette.HighlightedText)

    def _blend(c1: QColor, c2: QColor, w: float) -> QColor:
        """Blend two colors: w=1.0 is ``c1`` entirely, w=0.0 is ``c2``."""
        return QColor(
            int(c1.red() * w + c2.red() * (1 - w)),
            int(c1.green() * w + c2.green() * (1 - w)),
            int(c1.blue() * w + c2.blue() * (1 - w)),
        )

    # ── Text-color tiers, computed not palette-dependent ────────────
    # We deliberately do NOT use ``palette(mid)`` for muted text:
    # different IDA themes set ``mid`` very differently, and on some
    # palettes it collapses near the window background, rendering
    # read-only text invisible. Computing from a fixed blend of
    # WindowText + Window gives predictable legibility regardless of
    # what theme the user runs.
    soft_text = _blend(text, window, 0.72).name()      # read-only / group title
    muted_text = _blend(text, window, 0.55).name()     # sidebar unselected, hover hint
    disabled_text = _blend(text, window, 0.42).name()  # actually-disabled controls

    # Derived shades. Dark themes get lighter cards/inputs; light
    # themes get darker. The factor numbers below are QColor.lighter /
    # darker percentages — 115 means 15% lighter than the source.
    if is_dark:
        card_bg = window.lighter(115).name()
        input_bg = window.darker(110).name()
        ro_bg = window.darker(125).name()
        border = window.lighter(140).name()
        button_bg = window.lighter(120).name()
        button_hov = window.lighter(140).name()
        button_prs = window.lighter(105).name()
        check_brdr = window.lighter(170).name()
        hover_bg = window.lighter(130).name()
        sidebar_bg = window.darker(108).name()
    else:
        card_bg = window.darker(102).name()
        input_bg = "#ffffff"
        ro_bg = window.darker(105).name()
        border = window.darker(120).name()
        button_bg = window.lighter(108).name()
        button_hov = window.lighter(115).name()
        button_prs = window.darker(108).name()
        check_brdr = window.darker(140).name()
        hover_bg = window.darker(105).name()
        sidebar_bg = window.darker(103).name()

    a = accent.name()
    a_hov = accent.lighter(115).name()
    a_prs = accent.darker(115).name()
    a_text = accent_text.name()

    # ── Palette-aware SVG icons written to per-process temp files ───
    # Why files rather than data URLs: Qt's QSS image resolver does
    # NOT support `data:image/svg+xml;...` URIs (neither the `;utf8,`
    # nor `;base64,` form). ``QImage.loadFromData`` accepts them, but
    # the path through ``QSS image:`` does not. The result was that
    # checkbox checkmarks and combobox / spinbox chevrons rendered
    # as nothing at all — verified with a side-by-side test of utf8
    # vs base64 forms (both failed identically).
    #
    # The fix is to write the SVG content to a real file and reference
    # it via ``file://`` URL. We rebuild on every call so palette
    # changes (e.g. a user switches IDA theme between dialog opens)
    # are reflected. Files live in a per-process temp dir; the OS
    # cleans them up on process exit.
    #
    # The checkmark uses ``HighlightedText`` for contrast against the
    # accent-filled indicator; chevrons use ``soft_text`` so they
    # stand against input backgrounds without being shouty.
    check_svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'>"
        f"<path d='M2.5 6.5l2.3 2.3 4.7-5' fill='none' stroke='{a_text}' "
        "stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
    )
    chevron_down_svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'>"
        f"<path d='M2 4 L5 7 L8 4' fill='none' stroke='{soft_text}' "
        "stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
    )
    chevron_up_svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'>"
        f"<path d='M2 6 L5 3 L8 6' fill='none' stroke='{soft_text}' "
        "stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/></svg>"
    )

    icon_urls = _write_icon_cache({
        "check.svg": check_svg,
        "chevron_down.svg": chevron_down_svg,
        "chevron_up.svg": chevron_up_svg,
    })
    check_url = icon_urls["check.svg"]
    arrow_down_url = icon_urls["chevron_down.svg"]
    arrow_up_url = icon_urls["chevron_up.svg"]

    return f"""
QDialog {{
    background: palette(window);
    color: palette(window-text);
}}

/* === Sidebar (settings categories) ============================ */
QListWidget[settingsSidebar="true"] {{
    background: {sidebar_bg};
    border: none;
    border-right: 1px solid {border};
    padding: 10px 6px;
    outline: 0;
    font-size: 12px;
}}
QListWidget[settingsSidebar="true"]::item {{
    padding: 9px 14px;
    border-radius: 4px;
    margin: 2px 4px;
    color: {muted_text};
}}
QListWidget[settingsSidebar="true"]::item:hover {{
    color: palette(window-text);
    background: {hover_bg};
}}
QListWidget[settingsSidebar="true"]::item:selected {{
    color: {a_text};
    background: {a};
    font-weight: 600;
}}

/* === Group box → card ========================================= */
QGroupBox {{
    border: 1px solid {border};
    border-radius: 6px;
    margin-top: 18px;
    padding: 16px 12px 10px 12px;
    background: {card_bg};
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: {soft_text};
    font-weight: 700;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 1px;
}}

/* === Buttons =================================================== */
QPushButton {{
    background: {button_bg};
    color: palette(window-text);
    border: 1px solid {border};
    border-radius: 4px;
    padding: 6px 16px;
    min-width: 88px;
}}
QPushButton:hover    {{ background: {button_hov}; }}
QPushButton:pressed  {{ background: {button_prs}; }}
QPushButton:disabled {{ color: {disabled_text}; background: {button_bg}; }}

QPushButton[primary="true"] {{
    background: {a};
    color: {a_text};
    border: 1px solid {a};
}}
QPushButton[primary="true"]:hover    {{ background: {a_hov}; border-color: {a_hov}; }}
QPushButton[primary="true"]:pressed  {{ background: {a_prs}; border-color: {a_prs}; }}

QPushButton[iconButton="true"] {{
    min-width: 0;
    padding: 0;
    font-size: 14px;
    font-weight: bold;
}}

/* === Inputs ==================================================== */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {input_bg};
    color: palette(text);
    border: 1px solid {border};
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: {a};
    selection-color: {a_text};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {a};
}}
/* Read-only text uses ``soft_text`` (legible blend of WindowText +
 * Window), NOT palette(mid). The latter collapses near the
 * background on some IDA themes and renders paths invisible. The
 * darker ``ro_bg`` background plus the cursor-pinned-to-end of the
 * path content is what signals "read-only" — not unreadable text. */
QLineEdit:read-only {{ background: {ro_bg}; color: {soft_text}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {{
    color: {disabled_text};
}}

/* === Combobox dropdown + arrow ================================= */
QComboBox::drop-down {{
    border: none;
    width: 22px;
    subcontrol-position: right;
}}
QComboBox::down-arrow {{
    image: url("{arrow_down_url}");
    width: 10px;
    height: 10px;
}}
QComboBox QAbstractItemView {{
    background: {input_bg};
    color: palette(text);
    selection-background-color: {a};
    selection-color: {a_text};
    border: 1px solid {border};
    padding: 4px;
    outline: 0;
}}

/* === Spinbox up/down buttons + chevron arrows ================== */
QSpinBox, QDoubleSpinBox {{
    padding-right: 22px;  /* room for the up/down stack on the right */
}}
QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 18px;
    border: none;
    background: transparent;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 18px;
    border: none;
    background: transparent;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover,
QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {{
    background: {hover_bg};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    image: url("{arrow_up_url}");
    width: 10px;
    height: 10px;
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    image: url("{arrow_down_url}");
    width: 10px;
    height: 10px;
}}

/* === Checkboxes ================================================ */
QCheckBox {{ color: palette(window-text); spacing: 7px; }}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {check_brdr};
    border-radius: 3px;
    background: {input_bg};
}}
QCheckBox::indicator:hover   {{ border-color: {a}; }}
QCheckBox::indicator:checked {{
    background: {a};
    border-color: {a};
    image: url("{check_url}");
}}
QCheckBox::indicator:disabled {{ background: {ro_bg}; border-color: {border}; }}

/* === List widgets (exclusions) ================================= */
QListWidget {{
    background: {input_bg};
    color: palette(text);
    border: 1px solid {border};
    border-radius: 4px;
    padding: 2px;
    outline: 0;
}}
QListWidget::item {{ padding: 4px 6px; border-radius: 3px; }}
QListWidget::item:hover    {{ background: {hover_bg}; }}
QListWidget::item:selected {{ background: {a}; color: {a_text}; }}

/* === Section-heading labels (set property: heading=true) ====== */
QLabel[heading="true"] {{
    color: palette(window-text);
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.3px;
}}

/* === Bottom-bar separator (set property: separator=true) ====== */
QFrame[separator="true"] {{
    background: {border};
    max-height: 1px;
    min-height: 1px;
    border: none;
}}

/* === Scroll area / scrollbar polish =========================== */
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {border};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {check_brdr}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""


class ReadOnlyLineEdit(QLineEdit):
    """
    Custom QLineEdit that allows scrolling in read-only mode.

    Modifies standard QLineEdit behavior to maintain text selection and scrolling
    capabilities while preventing edits when in read-only mode.

    Attributes:
        _read_only (bool): Internal read-only state tracking
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._read_only = False

    def setReadOnly(self, state):
        self._read_only = state
        super().setReadOnly(state)
        self.setCursor(Qt.IBeamCursor)

    def mouseDoubleClickEvent(self, event):
        if not self._read_only:
            super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.setCursor(Qt.IBeamCursor)


class ExclusionsList(QFrame):
    """
    Custom list widget for managing excluded items.

    Provides interface for adding/removing exclusions entries with wildcard support
    and duplicate checking.

    Attributes:
        title (str): Title of the exclusions category
        entity_type (int): Type identifier for entities (1=libs, 2=APIs, etc.)
        list_widget (QListWidget): Widget containing exclusions entries
        remove_btn (QPushButton): Button for removing selected entries
    """

    def __init__(self, title, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Header with title and buttons. Title uses the heading=true
        # property so the QSS gives it a slightly heavier weight than
        # body text — without that, the four list titles blend into
        # the rest of the tab content.
        header = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setProperty("heading", True)
        header.addWidget(title_label)
        header.addStretch()

        # Use the iconButton property so the QSS strips the wide
        # default min-width and bumps the glyph weight. The minus
        # uses U+2212 (MINUS SIGN), not ASCII hyphen — the proper
        # glyph centers vertically in the button.
        add_btn = QPushButton("+")
        add_btn.setFixedSize(BUTTON_SIZE, BUTTON_SIZE)
        add_btn.setProperty("iconButton", True)
        add_btn.setToolTip(f"Add new {title}")

        self.remove_btn = QPushButton("−")
        self.remove_btn.setFixedSize(BUTTON_SIZE, BUTTON_SIZE)
        self.remove_btn.setProperty("iconButton", True)
        self.remove_btn.setToolTip(f"Remove selected {title}")
        self.remove_btn.setEnabled(False)  # Initially disabled

        header.addWidget(add_btn)
        header.addWidget(self.remove_btn)
        layout.addLayout(header)

        # List widget
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        self.list_widget.itemSelectionChanged.connect(self.update_remove_button)
        layout.addWidget(self.list_widget)

        # Connect signals
        add_btn.clicked.connect(self.add_item)
        self.remove_btn.clicked.connect(self.remove_selected)

        # Store title and determine entity type based on title
        self.title = title
        if "API" in title:
            self.entity_type = 2  # APIs
        elif "Lib" in title:
            self.entity_type = 1  # Libraries
        elif "String" in title:
            self.entity_type = 3  # Strings
        elif "Capa" in title:
            self.entity_type = 4  # Capa
        else:
            self.entity_type = None

    def get_entities_for_type(self, xrefer) -> List[str]:
        """
        Get list of entities matching this exclusions's type.

        Args:
            xrefer: XRefer object containing known entities

        Returns:
            List[str]: List of entity names that match this exclusions's type
        """
        entities = []

        if not self.entity_type:
            return entities

        for entity in xrefer.entities:
            if entity[2] != self.entity_type:  # Check entity type matches
                continue

            if self.entity_type == 2:  # APIs
                # For APIs, only match the name part after module
                name = entity[1].split(".")[-1]
            else:
                name = entity[1]

            entities.append(name)

        return entities

    def expand_wildcard_pattern(self, pattern: str) -> List[str]:
        """
        Expand a wildcard pattern to matching entity names.

        Converts wildcard pattern to regex and finds all matching entities,
        with confirmation for large match sets.

        Args:
            pattern (str): Pattern string with optional * wildcards

        Returns:
            List[str]: List of entity names matching the pattern
        """
        # Import here to avoid circular imports
        from xrefer.plugin import plugin_instance

        if not plugin_instance or not plugin_instance.xrefer_view:
            return [pattern]

        xrefer = plugin_instance.xrefer_view.xrefer_obj

        # Convert pattern to regex pattern
        regex_pattern = pattern.replace("*", ".*")
        if not pattern.startswith("*"):
            regex_pattern = "^" + regex_pattern
        if not pattern.endswith("*"):
            regex_pattern = regex_pattern + "$"

        try:
            matcher = re.compile(regex_pattern, re.IGNORECASE)

            # Get entities for this specific type
            all_entities = self.get_entities_for_type(xrefer)

            # Find matches
            matches = sorted(set(item for item in all_entities if matcher.search(item)))

            if not matches:
                QMessageBox.information(self, "No Matches", f"No matches found for pattern '{pattern}'", QMessageBox.Ok)
                return []

            # If there are a lot of matches, ask for confirmation
            if len(matches) > 10:
                msg = f"Pattern '{pattern}' matches {len(matches)} items.\n\nFirst 10 matches:\n" + "\n".join(f"- {m}" for m in matches[:10]) + "\n\nDo you want to add all matches?"

                confirm = QMessageBox.question(self, "Confirm Addition", msg, QMessageBox.Yes | QMessageBox.No)

                if confirm != QMessageBox.Yes:
                    return []

            return matches

        except re.error as e:
            QMessageBox.warning(self, "Invalid Pattern", f"Invalid wildcard pattern: {str(e)}", QMessageBox.Ok)
            return []

    def _item_exists(self, text: str) -> bool:
        """
        Check if item already exists in exclusions.

        Performs case-insensitive check for duplicate entries.

        Args:
            text (str): Text to check for duplicates

        Returns:
            bool: True if item exists (case-insensitive), False otherwise
        """
        text = text.lower()
        for i in range(self.list_widget.count()):
            if self.list_widget.item(i).text().lower() == text:
                return True
        return False

    def add_item(self):
        """Add new item(s) with wildcard support and duplicate checking"""
        text, ok = QInputDialog.getText(self, "Add Entry", "Enter new entry (use * for wildcards):")

        if not ok or not text.strip():
            return

        text = text.strip()

        # Check for wildcards
        if "*" in text:
            matches = self.expand_wildcard_pattern(text)
            for match in matches:
                if not self._item_exists(match):
                    self.list_widget.addItem(match)
        else:
            if self._item_exists(text):
                QMessageBox.warning(self, "Duplicate Entry", f"The entry '{text}' already exists in the list.", QMessageBox.Ok)
                return

            self.list_widget.addItem(text)

        # Sort items after addition
        self.sort_items()

    def sort_items(self) -> None:
        """
        Sort exclusions items alphabetically.

        Clears and repopulates list widget with sorted items.
        """
        items = [self.list_widget.item(i).text() for i in range(self.list_widget.count())]
        items.sort()
        self.list_widget.clear()
        self.list_widget.addItems(items)

    def update_remove_button(self):
        """Update remove button enabled state based on selection"""
        self.remove_btn.setEnabled(bool(self.list_widget.selectedItems()))

    def remove_selected(self):
        """Remove selected items and auto-select next item"""
        rows_to_remove = []
        for item in self.list_widget.selectedItems():
            rows_to_remove.append(self.list_widget.row(item))

        if not rows_to_remove:
            return

        # Sort rows in descending order to remove from bottom up
        rows_to_remove.sort(reverse=True)

        # Get the row to select after removal
        next_row = rows_to_remove[-1]  # Get smallest row number (will be our anchor point)

        # Remove items
        for row in rows_to_remove:
            self.list_widget.takeItem(row)

        # Select next item
        new_total = self.list_widget.count()
        if new_total > 0:
            # If we removed the last item(s), select the new last item
            if next_row >= new_total:
                next_row = new_total - 1
            # Select and ensure visible
            self.list_widget.setCurrentRow(next_row)
            self.list_widget.scrollToItem(self.list_widget.item(next_row))

    def get_items(self) -> List[str]:
        """
        Get all items in the exclusions.

        Returns:
            List[str]: All current exclusions entries
        """
        return [self.list_widget.item(i).text() for i in range(self.list_widget.count())]

    def set_items(self, items: List[str]) -> None:
        """
        Replace all exclusions items with new set.

        Args:
            items (List[str]): New items to populate exclusions with
        """
        self.list_widget.clear()
        self.list_widget.addItems(sorted(items))  # Add items in sorted order


class XReferSettingsDialog(QDialog):
    """
    Main dialog for configuring XRefer settings.

    Provides interface for modifying all XRefer settings including paths,
    exclusions, LLM configuration, and analysis options.

    Attributes:
        settings_manager (XReferSettingsManager): Manager for persisting settings
        settings (Dict): Current settings dictionary
        exclusions (Dict): Current exclusions dictionary
        original_exclusions (Dict): Copy of exclusions for change detection
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings_manager = XReferSettingsManager()
        self.settings = self.settings_manager.load_settings()
        self.exclusions = self.settings_manager.load_exclusions()
        self.original_exclusions = copy.deepcopy(self.exclusions)

        # Apply the palette-aware stylesheet first so all child widgets
        # constructed in initUI() pick up the styles on first paint.
        self.setStyleSheet(_build_dialog_qss())

        # Resizable instead of fixed-size: the previous fixed 1100x650
        # baked in one display density. minimumSize gives a sensible
        # floor on small displays; resize() sets a comfortable default.
        self.setMinimumSize(DIALOG_MIN_WIDTH, DIALOG_MIN_HEIGHT)
        self.resize(DIALOG_WIDTH, DIALOG_HEIGHT)
        self._center_on_screen()
        self.initUI()

    def _center_on_screen(self) -> None:
        """Center dialog on screen"""
        frame_geom = self.frameGeometry()
        center_point = QApplication.primaryScreen().availableGeometry().center()
        frame_geom.moveCenter(center_point)
        self.move(frame_geom.topLeft())

    def showEvent(self, event):
        """Re-center dialog when shown"""
        super().showEvent(event)
        frame_geom = self.frameGeometry()
        screen_center = QApplication.primaryScreen().geometry().center()
        frame_geom.moveCenter(screen_center)
        self.move(frame_geom.topLeft())

    def initUI(self):
        self.setWindowTitle("Configure XRefer")

        # Root layout: vertical, no padding so the sidebar / content
        # split spans edge-to-edge and the bottom button bar sits
        # flush at the bottom.
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Main content area: sidebar on the left, page stack on
        # the right. Replaces the old top-tab layout, which on
        # macOS rendered with an effectively-invisible selection
        # indicator. Sidebar tabs make the active section obvious
        # via the accent-filled row, and scale to any number of
        # future categories. ──────────────────────────────────────
        content = QHBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(0)

        self.sidebar = QListWidget()
        # The settingsSidebar property selects this list in the QSS;
        # without it, the list would pick up the generic QListWidget
        # styling we use for the exclusions lists.
        self.sidebar.setProperty("settingsSidebar", True)
        self.sidebar.setFixedWidth(SIDEBAR_WIDTH)
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.sidebar.setFocusPolicy(Qt.NoFocus)
        self.sidebar.addItem(QListWidgetItem("LLM"))
        self.sidebar.addItem(QListWidgetItem("Analysis"))
        self.sidebar.addItem(QListWidgetItem("Display"))
        self.sidebar.addItem(QListWidgetItem("Files"))
        self.sidebar.addItem(QListWidgetItem("Exclusions"))

        # Each page gets its own QScrollArea so cramped displays still
        # render every control — the previous fixed-size dialog would
        # have clipped controls on shorter screens. Margins on the
        # page widget itself (set inside each setup_*_tab method) give the
        # breathing room.
        llm_page = QWidget()
        analysis_page = QWidget()
        display_page = QWidget()
        files_page = QWidget()
        exclusion_page = QWidget()
        self.setup_llm_tab(llm_page)
        self.setup_analysis_tab(analysis_page)
        self.setup_display_tab(display_page)
        self.setup_files_tab(files_page)
        self.setup_exclusion_tab(exclusion_page)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._wrap_in_scroll(llm_page))
        self.pages.addWidget(self._wrap_in_scroll(analysis_page))
        self.pages.addWidget(self._wrap_in_scroll(display_page))
        self.pages.addWidget(self._wrap_in_scroll(files_page))
        self.pages.addWidget(self._wrap_in_scroll(exclusion_page))

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.setCurrentRow(0)

        content.addWidget(self.sidebar, 0)
        content.addWidget(self.pages, 1)

        content_container = QWidget()
        content_container.setLayout(content)
        root.addWidget(content_container, 1)

        # ── Bottom: 1px separator + right-aligned button row.
        # Primary action (Save) sits rightmost with accent fill;
        # Cancel is neutral. This matches platform-HIG conventions
        # for confirm/cancel dialogs and gives the dialog a clear
        # "structure" — header, content, footer — that was missing
        # when the buttons were full-width edge bars. ─────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setProperty("separator", True)
        root.addWidget(sep)

        button_bar = QHBoxLayout()
        # Larger bottom margin (20px vs 12 top) gives the buttons a
        # bit of breathing room against the dialog's bottom edge.
        # Symmetric top/bottom looked cramped on macOS where the
        # window-frame chrome is minimal.
        button_bar.setContentsMargins(16, 12, 16, 20)
        button_bar.setSpacing(8)
        button_bar.addStretch()

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        save_button = QPushButton("Save Settings")
        save_button.setProperty("primary", True)
        save_button.setDefault(True)  # Enter key triggers Save
        save_button.clicked.connect(self.save_settings)

        button_bar.addWidget(cancel_button)
        button_bar.addWidget(save_button)
        root.addLayout(button_bar)

    @staticmethod
    def _wrap_in_scroll(widget):
        """Wrap a page widget in a frameless, resizable QScrollArea.

        ``setWidgetResizable(True)`` lets the page widget grow to fill
        the available horizontal space, which is what we want for the
        Paths group (long path edits) and the exclusions grid. The
        scrollbar only appears when the page can't fit vertically.
        """
        sa = QScrollArea()
        sa.setWidget(widget)
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        return sa

    def setup_llm_tab(self, tab) -> None:
        """LLM / model configuration: enable LLM, the primary (cluster-analysis)
        model, and the optional separate categorization (lighter) model."""
        layout = QVBoxLayout(tab)
        # Page-level padding — without this the group-box cards sit
        # flush against the sidebar / scroll-area edges, which makes
        # them feel cramped on top-level dialog backgrounds.
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        # Model configuration group
        options_group = QGroupBox("Model")
        options_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        options_layout = QVBoxLayout(options_group)

        # Checkboxes
        self.llm_checkbox = QCheckBox("LLM Lookups")
        self.llm_checkbox.setToolTip("Enable llm-based categorization of APIs and libraries")
        self.llm_checkbox.setChecked(self.settings["llm_lookups"])
        self.llm_checkbox.stateChanged.connect(self.toggle_llm_options)

        # LLM Options
        llm_grid = QGridLayout()

        self.llm_model_combo = QComboBox()
        self.llm_model_combo.addItems(_curated_llm_models())
        self.llm_model_combo.setEditable(True)
        self.llm_model_combo.setInsertPolicy(QComboBox.NoInsert)
        self.llm_model_combo.setCurrentText(self.settings.get("llm_model_id", ""))
        self.llm_model_combo.setEnabled(self.settings["llm_lookups"])
        self.llm_model_combo.setToolTip("Enter the fully-qualified LLM identifier (e.g., provider/model)")

        line_edit = self.llm_model_combo.lineEdit()
        if line_edit:
            line_edit.setPlaceholderText("Select or type a model id…")
        make_combo_searchable(self.llm_model_combo)

        # ── Local model (Ollama) ─────────────────────────────────────
        # A checkbox reveals the API base field and switches the dropdown to
        # models listed from the Ollama server. Initial state is inferred from
        # the saved config (an ollama_* id or a non-empty api_base = local).
        from xrefer.llm.ollama import DEFAULT_API_BASE, is_ollama_model
        _api_base = self.settings.get("api_base", "") or ""
        _is_local = is_ollama_model(self.settings.get("llm_model_id", "")) or bool(_api_base)
        self.local_model_check = QCheckBox("Use a local model (Ollama)")
        self.local_model_check.setToolTip(
            "Run analysis against a local Ollama server instead of a hosted "
            "provider. Models are listed from the server and need no API key, "
            "but must support structured (JSON) output."
        )
        self.local_model_check.setChecked(_is_local)
        self.local_model_check.setEnabled(self.settings["llm_lookups"])
        self.local_model_check.toggled.connect(self.toggle_local_model)

        self.api_base_label = QLabel("API Base URL:")
        self.api_base_edit = QLineEdit(_api_base or (DEFAULT_API_BASE if _is_local else ""))
        self.api_base_edit.setPlaceholderText(DEFAULT_API_BASE)
        self.api_base_edit.setToolTip("Ollama server base URL (default http://localhost:11434).")
        self.api_base_edit.setEnabled(self.settings["llm_lookups"])
        self.api_base_edit.editingFinished.connect(self._on_api_base_changed)
        self.api_base_label.setVisible(_is_local)
        self.api_base_edit.setVisible(_is_local)
        if _is_local:
            self._populate_model_combo(True)

        # Refresh button: re-downloads litellm's model catalog so models
        # newer than the installed litellm version appear, then rebuilds
        # the dropdown. Wired into the model row in llm_grid below.
        self.refresh_models_btn = QPushButton("Refresh")
        self.refresh_models_btn.setToolTip(
            "Download the latest model catalog from litellm and rebuild the "
            "list (falls back to the bundled catalog if offline)"
        )
        self.refresh_models_btn.setEnabled(self.settings["llm_lookups"])
        self.refresh_models_btn.clicked.connect(self.refresh_model_list)

        self.api_key_edit = QLineEdit(self.settings["api_key"])
        self.api_key_edit.setEnabled(self.settings["llm_lookups"])
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setToolTip("API key for the selected LLM provider")

        model_row = QHBoxLayout()
        model_row.setContentsMargins(0, 0, 0, 0)
        model_row.setSpacing(6)
        model_row.addWidget(self.llm_model_combo, 1)
        model_row.addWidget(self.refresh_models_btn, 0)

        llm_grid.addWidget(QLabel("LLM Model ID:"), 0, 0)
        llm_grid.addLayout(model_row, 0, 1)
        llm_grid.addWidget(self.local_model_check, 1, 1)
        llm_grid.addWidget(self.api_base_label, 2, 0)
        llm_grid.addWidget(self.api_base_edit, 2, 1)
        llm_grid.addWidget(QLabel("API Key:"), 3, 0)
        llm_grid.addWidget(self.api_key_edit, 3, 1)

        options_layout.addWidget(self.llm_checkbox)
        options_layout.addLayout(llm_grid)

        # ── Optional second ("light") model for categorization ───────────
        # Progressive disclosure: by default the single model above does
        # everything. Enabling this reveals a fully independent model config so
        # the heavy cluster analysis (model above) and the bulk categorization
        # can use different models / keys / local servers — any mix.
        _use_light = bool(self.settings.get("use_light_model", False))
        _light_model_id = self.settings.get("light_model_id", "") or ""
        _light_api_base = self.settings.get("light_api_base", "") or ""
        _light_same_key = bool(self.settings.get("light_use_primary_key", True))
        _light_is_local = is_ollama_model(_light_model_id) or bool(_light_api_base)
        _light_api_key = self.settings.get("light_api_key", "") or ""

        self.use_light_model_check = QCheckBox(
            "Use a separate model for categorization (lighter tasks)")
        self.use_light_model_check.setToolTip(
            "Off: one model does everything.\n"
            "On: the model above runs the heavy cluster analysis, while a "
            "second, independently-configured model runs the bulk "
            "categorization (API / library tagging). Mix hosted + local freely."
        )
        self.use_light_model_check.setChecked(_use_light)
        self.use_light_model_check.setEnabled(self.settings["llm_lookups"])
        self.use_light_model_check.toggled.connect(self.toggle_use_light_model)
        options_layout.addWidget(self.use_light_model_check)

        self.light_container = QWidget()
        light_grid = QGridLayout(self.light_container)
        light_grid.setContentsMargins(18, 2, 0, 2)  # indent under the checkbox
        light_grid.setColumnStretch(1, 1)

        light_note = QLabel(
            "Cluster analysis uses the model above; categorization uses this one.")
        light_note.setWordWrap(True)
        light_grid.addWidget(light_note, 0, 0, 1, 2)

        self.light_model_combo = QComboBox()
        self.light_model_combo.setEditable(True)
        self.light_model_combo.setInsertPolicy(QComboBox.NoInsert)
        _light_le = self.light_model_combo.lineEdit()
        if _light_le:
            _light_le.setPlaceholderText("Select or type a model id…")
        self._fill_combo(self.light_model_combo, _light_is_local,
                         _light_api_base or DEFAULT_API_BASE)
        self.light_model_combo.setCurrentText(_light_model_id)
        make_combo_searchable(self.light_model_combo)

        self.light_refresh_btn = QPushButton("Refresh")
        self.light_refresh_btn.setToolTip("Rebuild the categorization-model list")
        self.light_refresh_btn.clicked.connect(self.refresh_light_model_list)

        self.light_local_check = QCheckBox("Use a local model (Ollama)")
        self.light_local_check.setToolTip(
            "Run categorization against a local Ollama server. Models are listed "
            "from the server and need no API key.")
        self.light_local_check.setChecked(_light_is_local)
        self.light_local_check.toggled.connect(self.toggle_light_local_model)

        self.light_api_base_label = QLabel("API Base URL:")
        self.light_api_base_edit = QLineEdit(
            _light_api_base or (DEFAULT_API_BASE if _light_is_local else ""))
        self.light_api_base_edit.setPlaceholderText(DEFAULT_API_BASE)
        self.light_api_base_edit.setToolTip(
            "Ollama server base URL (default http://localhost:11434).")
        self.light_api_base_edit.editingFinished.connect(self._on_light_api_base_changed)
        self.light_api_base_label.setVisible(_light_is_local)
        self.light_api_base_edit.setVisible(_light_is_local)

        self.light_same_key_check = QCheckBox("Use the main model's API key")
        self.light_same_key_check.setToolTip(
            "On (default): reuse the main model's API key for the categorization "
            "model (same provider, different tier).\n"
            "Off: give the categorization model its own API key below.")
        self.light_same_key_check.setChecked(_light_same_key)
        self.light_same_key_check.toggled.connect(self.toggle_light_same_key)

        self.light_api_key_edit = QLineEdit(_light_api_key)
        self.light_api_key_edit.setEchoMode(QLineEdit.Password)
        self.light_api_key_edit.setToolTip("API key for the categorization model")

        light_model_row = QHBoxLayout()
        light_model_row.setContentsMargins(0, 0, 0, 0)
        light_model_row.setSpacing(6)
        light_model_row.addWidget(self.light_model_combo, 1)
        light_model_row.addWidget(self.light_refresh_btn, 0)

        light_grid.addWidget(QLabel("Model ID:"), 1, 0)
        light_grid.addLayout(light_model_row, 1, 1)
        light_grid.addWidget(self.light_local_check, 2, 1)
        light_grid.addWidget(self.light_api_base_label, 3, 0)
        light_grid.addWidget(self.light_api_base_edit, 3, 1)
        light_grid.addWidget(self.light_same_key_check, 4, 1)
        light_grid.addWidget(QLabel("API Key:"), 5, 0)
        light_grid.addWidget(self.light_api_key_edit, 5, 1)

        options_layout.addWidget(self.light_container)
        self.light_container.setVisible(_use_light)
        self._update_light_enabled()

        layout.addWidget(options_group)
        layout.addStretch(1)

    def setup_analysis_tab(self, tab) -> None:
        """Analysis behaviour: cluster-analysis tuning, string enrichment, and
        the missing-file prompt option."""
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        analysis_options = self.settings.get("analysis_options", {})

        # Cluster analysis tuning
        cluster_group = QGroupBox("Cluster analysis")
        cluster_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        cluster_grid = QGridLayout(cluster_group)
        cluster_grid.setColumnStretch(1, 1)

        self.cluster_batch_size_spin = QSpinBox()
        self.cluster_batch_size_spin.setRange(5, 60)
        self.cluster_batch_size_spin.setValue(
            analysis_options.get("cluster_batch_size", 30)
        )
        self.cluster_batch_size_spin.setEnabled(self.settings["llm_lookups"])
        self.cluster_batch_size_spin.setToolTip(
            "Maximum clusters analyzed per stage-1 LLM batch. Lower "
            "values use more LLM calls but produce richer per-cluster "
            "output; higher values reduce call count but degrade per-"
            "cluster richness on most providers (the LLM's per-cluster "
            "output budget shrinks as the batch grows). Default 30."
        )

        # Stage-1 context strategy (full corpus vs bottom-up summarisation).
        self.cluster_context_mode_combo = QComboBox()
        for _val, _lbl in (
            ("auto", "Auto (local: summarise; cloud: full when it fits)"),
            ("full", "Full corpus (block if it overflows)"),
            ("hierarchical", "Hierarchical (summarise bottom-up)"),
        ):
            self.cluster_context_mode_combo.addItem(_lbl, _val)
        _mode = analysis_options.get("cluster_context_mode", "auto")
        _mode_idx = self.cluster_context_mode_combo.findData(_mode)
        self.cluster_context_mode_combo.setCurrentIndex(_mode_idx if _mode_idx >= 0 else 0)
        self.cluster_context_mode_combo.setEnabled(self.settings["llm_lookups"])
        self.cluster_context_mode_combo.setToolTip(
            "Stage-1 cluster-analysis strategy.\n"
            "• Auto (default): local (Ollama) models always summarise child "
            "clusters bottom-up so each call stays small and laptop memory "
            "stays bounded; commercial models send the whole corpus when it "
            "fits the context window and summarise only when it doesn't.\n"
            "• Full corpus: always send everything; block if it overflows.\n"
            "• Hierarchical: always summarise bottom-up (also the A/B lever vs "
            "Full on a model that fits the full corpus)."
        )

        # Hierarchical/local per-call token budget (also caps Ollama num_ctx).
        self.local_max_call_tokens_spin = QSpinBox()
        self.local_max_call_tokens_spin.setRange(4096, 1048576)
        self.local_max_call_tokens_spin.setSingleStep(4096)
        self.local_max_call_tokens_spin.setValue(int(analysis_options.get("local_max_call_tokens", 32768)))
        self.local_max_call_tokens_spin.setEnabled(self.settings["llm_lookups"])
        self.local_max_call_tokens_spin.setToolTip(
            "Hierarchical/local per-call token budget. Also caps Ollama's "
            "num_ctx, so it directly bounds KV-cache memory: ~32k ≈ ~2 GB (F16) "
            "for a 12B model. Raise for fewer/larger calls if you have RAM "
            "headroom; lower to keep more memory free. Ignored by the full-"
            "corpus path. Default 32768."
        )

        cluster_grid.addWidget(QLabel("Cluster Batch Size:"), 0, 0)
        cluster_grid.addWidget(self.cluster_batch_size_spin, 0, 1)
        cluster_grid.addWidget(QLabel("Cluster Context Mode:"), 1, 0)
        cluster_grid.addWidget(self.cluster_context_mode_combo, 1, 1)
        cluster_grid.addWidget(QLabel("Local Max Call Tokens:"), 2, 0)
        cluster_grid.addWidget(self.local_max_call_tokens_spin, 2, 1)
        layout.addWidget(cluster_group)

        # Enrichment and prompts
        other_group = QGroupBox("Enrichment and prompts")
        other_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        other_layout = QVBoxLayout(other_group)

        self.git_checkbox = QCheckBox("Enable Git lookups for strings")
        self.git_checkbox.setToolTip("Enable Git repository-based string categorization")
        self.git_checkbox.setChecked(self.settings["git_lookups"])

        self.prompt_checkbox = QCheckBox("Disable prompts for missing API trace and Capa files")
        self.prompt_checkbox.setToolTip("Disable prompts when Capa results or API trace files are missing")
        self.prompt_checkbox.setChecked(self.settings["suppress_notifications"])

        other_layout.addWidget(self.git_checkbox)
        other_layout.addWidget(self.prompt_checkbox)
        layout.addWidget(other_group)

        layout.addStretch(1)

    def setup_display_tab(self, tab) -> None:
        """Presentation / view options (graphs, banners, panel width)."""
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        display_group = QGroupBox("Display Options")
        display_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        display_layout = QGridLayout(display_group)
        display_layout.setHorizontalSpacing(50)  # Space between columns

        # Left column options
        self.auto_size_graphs = QCheckBox("Enable auto-resizing for graphs")
        self.auto_size_graphs.setToolTip("Automatically resize view when displaying graphs and clusters")
        self.auto_size_graphs.setChecked(self.settings["display_options"]["auto_size_graphs"])

        self.hide_llm_disclaimer = QCheckBox("Hide LLM disclaimers")
        self.hide_llm_disclaimer.setToolTip("Hide disclaimers about LLM-based analysis in views")
        self.hide_llm_disclaimer.setChecked(self.settings["display_options"]["hide_llm_disclaimer"])

        # Right column options
        self.show_help_banner = QCheckBox("Show help banner")
        self.show_help_banner.setToolTip("Show help banner with keyboard shortcuts at top of views")
        self.show_help_banner.setChecked(self.settings["display_options"]["show_help_banner"])

        # Panel width layout for right column
        width_layout = QHBoxLayout()
        width_layout.addWidget(QLabel("Default Panel Width: "))
        self.panel_width_spin = QSpinBox()
        self.panel_width_spin.setRange(400, 2000)  # Reasonable range for panel width
        self.panel_width_spin.setValue(self.settings["display_options"]["default_panel_width"])
        self.panel_width_spin.setSuffix(" px")
        self.panel_width_spin.setToolTip("Default width of the XRefer panel in pixels")
        width_layout.addWidget(self.panel_width_spin)
        width_layout.addStretch()

        # Graph node-detail (D) artifact cap: a checkbox reveals/enables a
        # spinbox. Off = show every artifact (current behaviour); on = cap each
        # type (imports/strings/capa/libs) per node.
        self.cap_graph_artifacts = QCheckBox("Cap artifacts per type in graph nodes")
        self.cap_graph_artifacts.setToolTip(
            "In the graph node-detail view (press D), limit how many of each artifact type "
            "(imports / strings / capa / libs) each node lists, with a dim '(+N more)' "
            "overflow line. Unchecked = show all artifacts."
        )
        self.cap_graph_artifacts.setChecked(
            self.settings["display_options"].get("cap_graph_node_artifacts", False)
        )

        cap_layout = QHBoxLayout()
        cap_layout.addWidget(QLabel("Cap per type: "))
        self.graph_artifact_cap_spin = QSpinBox()
        self.graph_artifact_cap_spin.setRange(1, 50)
        self.graph_artifact_cap_spin.setValue(
            self.settings["display_options"].get("graph_node_artifact_cap", 6)
        )
        self.graph_artifact_cap_spin.setToolTip("Maximum of each artifact type shown per node when capping is on.")
        self.graph_artifact_cap_spin.setEnabled(self.cap_graph_artifacts.isChecked())
        self.cap_graph_artifacts.toggled.connect(self.graph_artifact_cap_spin.setEnabled)
        cap_layout.addWidget(self.graph_artifact_cap_spin)
        cap_layout.addStretch()

        # Create spacer columns to properly position the content
        display_layout.setColumnStretch(0, 1)  # Left content column
        display_layout.setColumnStretch(1, 1)  # Middle spacing
        display_layout.setColumnStretch(2, 1)  # Right content column
        display_layout.setColumnStretch(3, 1)  # Right margin

        # Add widgets to grid layout - using columns 0 and 2 to leave column 1 as spacing
        display_layout.addWidget(self.auto_size_graphs, 0, 0)
        display_layout.addWidget(self.hide_llm_disclaimer, 1, 0)
        display_layout.addWidget(self.cap_graph_artifacts, 2, 0)
        display_layout.addWidget(self.show_help_banner, 0, 2)
        display_layout.addLayout(width_layout, 1, 2)
        display_layout.addLayout(cap_layout, 2, 2)

        layout.addWidget(display_group)
        layout.addStretch(1)

    def setup_files_tab(self, tab) -> None:
        """File locations: the editable per-sample input/output paths, plus the
        read-only global ``~/.xrefer`` application-data locations (reference)."""
        from qtpy.QtCore import QUrl
        from qtpy.QtGui import QDesktopServices, QFontDatabase

        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        # ── Editable per-sample input/output paths ───────────────────────
        paths_group = QGroupBox("Sample files")
        paths_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        paths_layout = QGridLayout(paths_group)

        path_configs = [("analysis", "Analysis Path"), ("trace", "API Trace Path"), ("capa", "Capa Results Path"), ("xrefs", "Indirect XRefs Path"), ("categories", "Categories Cache Path")]

        self.path_widgets = {}
        row = 0
        for path_type, label in path_configs:
            paths_layout.addWidget(QLabel(label), row, 0)

            # Path edit. The hover tooltip carries the full path and the cursor
            # is pinned to the end so the filename stays visible when clipped.
            path_value = self.settings["paths"][path_type]
            path_edit = ReadOnlyLineEdit(path_value)
            font = path_edit.font()
            font.setPointSize(font.pointSize() - 1)
            path_edit.setFont(font)
            path_edit.setToolTip(path_value or f"{label} (not configured)")
            path_edit.setCursorPosition(len(path_edit.text()))
            path_edit.textChanged.connect(
                lambda text, e=path_edit, lbl=label: (
                    e.setToolTip(text or f"{lbl} (not configured)"),
                    e.setCursorPosition(len(text)),
                )
            )
            if self.settings["use_default_paths"][path_type]:
                path_edit.setReadOnly(True)
            paths_layout.addWidget(path_edit, row, 1)

            default_check = QCheckBox("Default")
            default_check.setChecked(self.settings["use_default_paths"][path_type])
            default_check.setToolTip("Use default path")
            paths_layout.addWidget(default_check, row, 2)

            browse_btn = QPushButton("Browse")
            browse_btn.setEnabled(not self.settings["use_default_paths"][path_type])
            browse_btn.setToolTip("Browse for file")
            paths_layout.addWidget(browse_btn, row, 3)

            self.path_widgets[path_type] = {"edit": path_edit, "check": default_check, "browse": browse_btn, "default_path": self.settings["paths"][path_type]}

            default_check.stateChanged.connect(lambda state, t=path_type: self.toggle_path_default(t, state))
            browse_btn.clicked.connect(lambda _, t=path_type: self.browse_path(t))

            row += 1

        layout.addWidget(paths_group)

        # ── Read-only application data (the global ~/.xrefer directory) ──
        # Palette-derived colours so the status dots track the active theme.
        pal = self.palette()
        accent = pal.color(QPalette.Highlight).name()
        text = pal.color(QPalette.WindowText)
        window = pal.color(QPalette.Window)
        muted = QColor(
            (text.red() + window.red()) // 2,
            (text.green() + window.green()) // 2,
            (text.blue() + window.blue()) // 2,
        ).name()
        mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)

        sdir = self.settings_manager.settings_dir
        # (display name, absolute path) for the global, shared xrefer data.
        rows = [
            ("Folder", sdir),
            ("Settings", self.settings_manager.settings_file),
            ("Exclusions", self.settings_manager.exclusion_file),
            ("Categories", os.path.join(sdir, "xrefer_categories.json")),
            ("Lock", self.settings_manager.lockfile),
        ]

        group = QGroupBox("Settings and Shared Data")
        group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(12)

        caption = QLabel(
            "Where XRefer stores its settings and shared data on this machine. "
            "Shown for reference — these can't be edited here."
        )
        caption.setWordWrap(True)
        caption.setStyleSheet(f"color: {muted};")
        group_layout.addWidget(caption)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(9)
        grid.setColumnStretch(2, 1)

        for r, (name, path) in enumerate(rows):
            exists = os.path.exists(path)

            dot = QLabel("●")  # ●
            dot.setStyleSheet(f"color: {accent if exists else muted};")
            dot.setFixedWidth(12)
            dot.setAlignment(Qt.AlignCenter)
            dot.setToolTip("Present on disk" if exists else "Not created yet")

            name_label = QLabel(name)
            name_label.setMinimumWidth(80)

            field = ReadOnlyLineEdit(path)
            field.setReadOnly(True)
            field.setFont(mono)
            field.setToolTip(path)
            field.setCursorPosition(0)

            copy_btn = QPushButton("Copy")
            copy_btn.setFixedWidth(60)
            copy_btn.setToolTip("Copy this path to the clipboard")
            copy_btn.clicked.connect(lambda _checked=False, p=path: self._copy_location_path(p))

            grid.addWidget(dot, r, 0)
            grid.addWidget(name_label, r, 1)
            grid.addWidget(field, r, 2)
            grid.addWidget(copy_btn, r, 3)

        group_layout.addLayout(grid)

        # Footer: a small legend on the left, open-folder action on the right.
        footer = QHBoxLayout()
        legend = QLabel(
            f'<span style="color:{accent}">●</span> present&nbsp;&nbsp;&nbsp;'
            f'<span style="color:{muted}">●</span> not created yet'
        )
        footer.addWidget(legend)
        footer.addStretch(1)
        open_btn = QPushButton("Open Folder")
        open_btn.setToolTip("Open the ~/.xrefer folder in your file manager")
        open_btn.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.settings_manager.settings_dir))
        )
        footer.addWidget(open_btn)
        group_layout.addLayout(footer)

        layout.addWidget(group)
        layout.addStretch(1)

    def _copy_location_path(self, text: str) -> None:
        """Copy ``text`` to the system clipboard (Data Locations copy buttons)."""
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)

    def setup_exclusion_tab(self, tab) -> None:
        """
        Initialize the exclusions management tab.

        Sets up UI elements for managing different types of exclusions.

        Args:
            tab: Tab widget to populate with exclusions controls
        """
        layout = QVBoxLayout(tab)
        # Match the general-tab page padding so both pages have the
        # same breathing room when the user switches between them.
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        # Enable Exclusions checkbox
        self.enable_exclusion_checkbox = QCheckBox("Enable Exclusions")
        self.enable_exclusion_checkbox.setToolTip("Enable/disable exclusions filtering of results")
        self.enable_exclusion_checkbox.setChecked(self.settings["enable_exclusions"])
        layout.addWidget(self.enable_exclusion_checkbox)

        # Path selection
        path_layout = QGridLayout()
        path_layout.addWidget(QLabel("Exclusions Path:"), 0, 0)

        exclusions_path_value = self.settings["paths"]["exclusions"]
        self.exclusion_path_edit = ReadOnlyLineEdit(exclusions_path_value)
        font = self.exclusion_path_edit.font()
        font.setPointSize(font.pointSize() - 1)
        self.exclusion_path_edit.setFont(font)
        # Full path in the tooltip; cursor pinned to the end so the
        # filename stays visible when the displayed text is clipped.
        self.exclusion_path_edit.setToolTip(
            exclusions_path_value or "Path to exclusions configuration file"
        )
        self.exclusion_path_edit.setCursorPosition(len(self.exclusion_path_edit.text()))
        self.exclusion_path_edit.textChanged.connect(
            lambda text, e=self.exclusion_path_edit: (
                e.setToolTip(text or "Path to exclusions configuration file"),
                e.setCursorPosition(len(text)),
            )
        )
        if self.settings["use_default_paths"]["exclusions"]:
            self.exclusion_path_edit.setReadOnly(True)
        path_layout.addWidget(self.exclusion_path_edit, 0, 1)

        self.exclusion_default_check = QCheckBox("Default")
        self.exclusion_default_check.setToolTip("Use default exclusions path")
        self.exclusion_default_check.setChecked(self.settings["use_default_paths"]["exclusions"])
        path_layout.addWidget(self.exclusion_default_check, 0, 2)

        self.exclusion_browse_btn = QPushButton("Browse")
        self.exclusion_browse_btn.setToolTip("Browse for exclusions file")
        self.exclusion_browse_btn.setEnabled(not self.settings["use_default_paths"]["exclusions"])
        path_layout.addWidget(self.exclusion_browse_btn, 0, 3)

        layout.addLayout(path_layout)

        # Exclusions lists configuration
        exclusion_configs = [("apis", "API References"), ("libs", "Lib References"), ("strings", "String References"), ("capa", "Capa References")]

        lists_layout = QGridLayout()
        self.exclusion_lists = {}

        for col, (list_type, title) in enumerate(exclusion_configs):
            list_widget = ExclusionsList(title)
            list_widget.set_items(self.exclusions[list_type])
            lists_layout.addWidget(list_widget, 0, col)
            self.exclusion_lists[list_type] = list_widget

        layout.addLayout(lists_layout)

        # Connect exclusions path controls
        self.exclusion_default_check.stateChanged.connect(lambda state: self.toggle_path_default("exclusions", state))
        self.exclusion_browse_btn.clicked.connect(lambda: self.browse_path("exclusions"))

    def toggle_llm_options(self, state):
        """Toggle LLM-related controls based on checkbox state"""
        enabled = state == Qt.Checked
        self.llm_model_combo.setEnabled(enabled)
        self.refresh_models_btn.setEnabled(enabled)
        self.api_key_edit.setEnabled(enabled)
        self.cluster_batch_size_spin.setEnabled(enabled)
        self.cluster_context_mode_combo.setEnabled(enabled)
        self.local_max_call_tokens_spin.setEnabled(enabled)
        self.local_model_check.setEnabled(enabled)
        self.api_base_edit.setEnabled(enabled)
        self.use_light_model_check.setEnabled(enabled)
        self._update_light_enabled()

    def refresh_model_list(self) -> None:
        """Re-download litellm's model catalog and rebuild the dropdown.

        The dropdown is normally populated from ``litellm.model_cost`` — the
        catalog table baked into the *installed* litellm package. This
        re-fetches litellm's live catalog
        (``model_prices_and_context_window.json``) so models newer than the
        installed litellm version show up, reassigns ``litellm.model_cost``,
        and repopulates the combo through the same ``_curated_llm_models``
        filter used at startup.

        Synchronous on purpose: IDA's Qt loop is single-threaded and xrefer
        must not touch IDA/Qt from a worker thread (see the async-experiment
        post-mortems in memory). A wait cursor covers the one-shot fetch;
        litellm falls back to its bundled catalog if the network is
        unavailable, so this never hard-fails.
        """
        combo = self.llm_model_combo
        typed = combo.currentText()
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            if self.local_model_check.isChecked():
                # Local mode: list installed models straight from the Ollama
                # server (litellm's catalog has none of them).
                from xrefer.llm.ollama import list_models
                models = list_models(self.api_base_edit.text())
                print(f"[XRefer] Local models from Ollama: {len(models)}")
            else:
                try:
                    import litellm
                    url = getattr(
                        litellm,
                        "model_cost_map_url",
                        "https://raw.githubusercontent.com/BerriAI/litellm/main/"
                        "model_prices_and_context_window.json",
                    )
                    fresh = litellm.get_model_cost_map(url)
                    if isinstance(fresh, dict) and fresh:
                        litellm.model_cost = fresh
                except Exception as exc:
                    print(f"[XRefer] Model list refresh: catalog fetch failed "
                          f"({exc}); using cached catalog")
                models = _curated_llm_models()
                print(f"[XRefer] Model list refreshed: {len(models)} compatible models")
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(models)
            combo.setCurrentText(typed)  # preserve the user's selection
            combo.blockSignals(False)
        finally:
            QApplication.restoreOverrideCursor()

    def toggle_local_model(self, checked: bool) -> None:
        """Reveal the API base field + switch the model dropdown source when
        'Use a local model (Ollama)' is toggled."""
        self.api_base_label.setVisible(checked)
        self.api_base_edit.setVisible(checked)
        if checked and not self.api_base_edit.text().strip():
            from xrefer.llm.ollama import DEFAULT_API_BASE
            self.api_base_edit.setText(DEFAULT_API_BASE)
        # The key isn't needed for local models (kept editable for a secured
        # server); hint that in the placeholder.
        self.api_key_edit.setPlaceholderText(
            "(not required for local models)" if checked else "")
        self._populate_model_combo(checked)

    def _on_api_base_changed(self) -> None:
        """Re-list local models when the base URL changes (local mode only)."""
        if self.local_model_check.isChecked():
            self._populate_model_combo(True)

    def _populate_model_combo(self, local: bool) -> None:
        """Fill the model dropdown from the right source — installed Ollama
        models when local, the curated hosted catalog otherwise — preserving
        the current text so a saved id stays selected even if absent."""
        combo = self.llm_model_combo
        typed = combo.currentText()
        if local:
            from xrefer.llm.ollama import list_models
            models = list_models(self.api_base_edit.text())
        else:
            models = _curated_llm_models()
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(models)
        combo.setCurrentText(typed)
        combo.blockSignals(False)

    # ── Shared combo population (used by the light-model section) ─────────
    def _fill_combo(self, combo, local: bool, api_base_text: str) -> None:
        """Populate ``combo`` from the right source — installed Ollama models
        when ``local``, else the curated hosted catalog — preserving the typed
        text so a saved id stays selected."""
        typed = combo.currentText()
        if local:
            from xrefer.llm.ollama import list_models
            models = list_models(api_base_text)
        else:
            models = _curated_llm_models()
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(models)
        combo.setCurrentText(typed)
        combo.blockSignals(False)

    def _refresh_combo(self, combo, local: bool, api_base_text: str) -> None:
        """Re-fetch the model catalog (litellm) or re-list Ollama models, then
        repopulate ``combo``. Synchronous (IDA's Qt loop is single-threaded);
        falls back to the bundled catalog when offline."""
        typed = combo.currentText()
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            if local:
                from xrefer.llm.ollama import list_models
                models = list_models(api_base_text)
            else:
                try:
                    import litellm
                    url = getattr(
                        litellm, "model_cost_map_url",
                        "https://raw.githubusercontent.com/BerriAI/litellm/main/"
                        "model_prices_and_context_window.json",
                    )
                    fresh = litellm.get_model_cost_map(url)
                    if isinstance(fresh, dict) and fresh:
                        litellm.model_cost = fresh
                except Exception as exc:
                    print(f"[XRefer] Model list refresh failed ({exc}); using cached catalog")
                models = _curated_llm_models()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(models)
            combo.setCurrentText(typed)
            combo.blockSignals(False)
        finally:
            QApplication.restoreOverrideCursor()

    # ── Light (categorization) model handlers ────────────────────────────
    def toggle_use_light_model(self, checked: bool) -> None:
        """Reveal / hide the separate categorization-model config."""
        self.light_container.setVisible(checked)
        self._update_light_enabled()

    def toggle_light_local_model(self, checked: bool) -> None:
        """Reveal the light API-base field + switch its dropdown source."""
        self.light_api_base_label.setVisible(checked)
        self.light_api_base_edit.setVisible(checked)
        if checked and not self.light_api_base_edit.text().strip():
            from xrefer.llm.ollama import DEFAULT_API_BASE
            self.light_api_base_edit.setText(DEFAULT_API_BASE)
        self._fill_combo(self.light_model_combo, checked, self.light_api_base_edit.text())
        self._update_light_key_enabled()

    def _on_light_api_base_changed(self) -> None:
        if self.light_local_check.isChecked():
            self._fill_combo(self.light_model_combo, True, self.light_api_base_edit.text())

    def refresh_light_model_list(self) -> None:
        self._refresh_combo(self.light_model_combo, self.light_local_check.isChecked(),
                            self.light_api_base_edit.text())

    def toggle_light_same_key(self, checked: bool) -> None:
        self._update_light_key_enabled()

    def _update_light_key_enabled(self) -> None:
        """The light API-key field is only relevant when the section is active,
        a separate key is wanted, and the model isn't local."""
        on = self.llm_checkbox.isChecked() and self.use_light_model_check.isChecked()
        local = self.light_local_check.isChecked()
        same = self.light_same_key_check.isChecked()
        self.light_api_key_edit.setEnabled(on and not same and not local)
        self.light_api_key_edit.setPlaceholderText(
            "(uses the main model's key)" if same
            else ("(not required for local models)" if local else ""))

    def _update_light_enabled(self) -> None:
        """Enable the light-model controls only when LLM lookups AND the
        separate-model toggle are both on."""
        on = self.llm_checkbox.isChecked() and self.use_light_model_check.isChecked()
        for w in (self.light_model_combo, self.light_refresh_btn, self.light_local_check,
                  self.light_api_base_edit, self.light_same_key_check):
            w.setEnabled(on)
        self._update_light_key_enabled()

    def toggle_path_default(self, path_type, state):
        """Toggle path edit read-only state based on Default checkbox"""
        if path_type == "exclusions":
            self.exclusion_browse_btn.setEnabled(not state)
            self.exclusion_path_edit.setReadOnly(state)
            if state:
                self.exclusion_path_edit.setText(self.settings["paths"]["exclusions"])
            else:
                self.exclusion_path_edit.clear()
        else:
            widgets = self.path_widgets[path_type]
            widgets["browse"].setEnabled(not state)
            widgets["edit"].setReadOnly(state)
            if state:
                widgets["edit"].setText(widgets["default_path"])
            else:
                widgets["edit"].clear()

    def browse_path(self, path_type: str) -> None:
        """Handle browse button clicks for path selection"""
        file_filter = FILE_FILTERS.get(path_type, FILE_FILTERS["default"])
        dialog_title = f"Select {path_type.title()} File"

        path, _ = QFileDialog.getOpenFileName(self, dialog_title, "", file_filter)
        if not path:
            return

        if path_type == "exclusions":
            self.exclusion_path_edit.setText(path)
        else:
            self.path_widgets[path_type]["edit"].setText(path)

    def save_settings(self) -> None:
        """
        Save current settings and exclusions to disk.

        Updates both settings and exclusions files, handles exclusions state changes,
        and triggers necessary UI updates.
        """
        exclusions_was_enabled = self.settings.get("enable_exclusions", True)
        exclusions_now_enabled = self.enable_exclusion_checkbox.isChecked()
        exclusions_state_changed = exclusions_was_enabled != exclusions_now_enabled

        settings = {
            "llm_lookups": self.llm_checkbox.isChecked(),
            "git_lookups": self.git_checkbox.isChecked(),
            "suppress_notifications": self.prompt_checkbox.isChecked(),
            "llm_model_id": self.llm_model_combo.currentText(),
            "api_key": self.api_key_edit.text(),
            "api_base": self.api_base_edit.text().strip() if self.local_model_check.isChecked() else "",
            # Optional separate "light" model for categorization.
            "use_light_model": self.use_light_model_check.isChecked(),
            "light_model_id": self.light_model_combo.currentText(),
            "light_api_base": self.light_api_base_edit.text().strip() if self.light_local_check.isChecked() else "",
            "light_use_primary_key": self.light_same_key_check.isChecked(),
            # Store the light key only when a separate one is wanted (else reuse
            # the primary key at config-resolve time).
            "light_api_key": "" if self.light_same_key_check.isChecked() else self.light_api_key_edit.text(),
            "enable_exclusions": self.enable_exclusion_checkbox.isChecked(),
            "analysis_options": {
                "cluster_batch_size": self.cluster_batch_size_spin.value(),
                "cluster_context_mode": self.cluster_context_mode_combo.currentData() or "auto",
                "local_max_call_tokens": self.local_max_call_tokens_spin.value(),
            },
            # Add display options
            "display_options": {
                "auto_size_graphs": self.auto_size_graphs.isChecked(),
                "hide_llm_disclaimer": self.hide_llm_disclaimer.isChecked(),
                "show_help_banner": self.show_help_banner.isChecked(),
                "default_panel_width": self.panel_width_spin.value(),
                "cap_graph_node_artifacts": self.cap_graph_artifacts.isChecked(),
                "graph_node_artifact_cap": self.graph_artifact_cap_spin.value(),
            },
            "use_default_paths": {"exclusions": self.exclusion_default_check.isChecked()},
            "paths": {"exclusions": self.exclusion_path_edit.text()},
        }

        for path_type in self.path_widgets:
            settings["use_default_paths"][path_type] = self.path_widgets[path_type]["check"].isChecked()
            settings["paths"][path_type] = self.path_widgets[path_type]["edit"].text()

        # Get current exclusions
        exclusions: ExclusionData = {list_type: list_widget.get_items() for list_type, list_widget in self.exclusion_lists.items()}

        # Check if exclusions have changed
        exclusions_changed = False
        for list_type in exclusions:
            if set(exclusions[list_type]) != set(self.original_exclusions.get(list_type, [])):
                exclusions_changed = True
                break

        # Store both settings and exclusions
        self.settings_manager.save_settings(settings)
        self.settings_manager.save_exclusions(exclusions)

        # Import here instead of at the top to avoid a partial import
        from xrefer.plugin import plugin_instance

        if plugin_instance and plugin_instance.xrefer_view:
            plugin_instance.xrefer_view.xrefer_obj.reload_settings()

            # Repopulate tables if either exclusions changed or exclusions state changed
            if exclusions_changed or exclusions_state_changed:
                plugin_instance.xrefer_view.xrefer_obj.clear_affected_function_tables()
            # Repaint the current view so display-only changes (e.g. the graph
            # artifact cap, panel width) take effect immediately instead of
            # waiting for the next keystroke.
            plugin_instance.xrefer_view.update(True)

        self.accept()


class MissingFilesDialog(QDialog):
    """
    Dialog for handling missing required files.

    Displays information about missing analysis files (trace, CAPA, etc.)
    and allows user to choose whether to proceed with analysis.

    Attributes:
        missing_files (Dict[str, str]): Dictionary mapping file types to missing paths
    """

    def __init__(self, missing_files: Dict[str, str], parent=None):
        super().__init__(parent)
        self.missing_files = missing_files
        self.initUI()

    def format_path(self, path: str, max_width: int = 500) -> str:
        """Format path to fit within specified width with ellipsis"""
        if not path:
            return ""

        metrics = QFontMetrics(QFont("Arial", 9))
        if metrics.horizontalAdvance(path) <= max_width:
            return path

        dir_name = os.path.dirname(path)
        file_name = os.path.basename(path)
        ellipsis_text = "/.../"

        # Calculate available space for directory
        ellipsis_width = metrics.horizontalAdvance(ellipsis_text)
        filename_width = metrics.horizontalAdvance(file_name)
        available_width = max_width - ellipsis_width - filename_width

        if available_width <= 0:
            return "..." + file_name[-30:]

        # Progressively truncate directory parts
        parts = dir_name.split(os.sep)
        while len(parts) > 1 and metrics.horizontalAdvance(os.sep.join(parts)) > available_width:
            if len(parts) > 3:
                parts = parts[:2] + ["..."] + parts[-1:]
            else:
                parts = ["..."] + parts[-1:]
            if len(parts) <= 2:
                break

        return f"{os.sep.join(parts)}{ellipsis_text}{file_name}"

    def initUI(self) -> None:
        """
        Initialize dialog user interface.

        Creates layout with missing file information, explanations of
        file purposes, and proceed/cancel buttons. Handles scrolling
        for many missing files.
        """
        # Set window properties
        self.setWindowTitle("XRefer Configuration Notice")
        self.setMinimumSize(650, 200)
        self.setMaximumSize(800, 600)  # Maximum reasonable size

        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Create scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        # Create content widget
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 0, 0, 0)

        # Add main message
        message = QLabel(
            "XRefer is a binary navigation tool that provides a context aware navigation "
            "interface by ingestion and processing of multiple data sources. Some of this "
            "data (strings, apis, libs etc) is extracted from within the IDB, while some "
            "can be ingested from external files. The more data available to XRefer, the "
            "better results it will produce. Following external files were found missing:"
        )
        message.setWordWrap(True)
        message.setFont(QFont("Arial", 10))
        layout.addWidget(message)

        # Create frame for missing files
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        frame_layout = QVBoxLayout(frame)
        frame_layout.setSpacing(10)
        frame_layout.setContentsMargins(15, 15, 15, 15)

        # Add missing file descriptions
        descriptions = {
            "trace": (
                "API Trace File Missing",
                "Analysis archive from VMRay (archive.zip) or Cape Sandbox (*.json) "
                "can be ingested. These enable enrichment of the cluster analysis and"
                "navigation interface with API call information.",
            ),
            "capa": ("CAPA Analysis File Missing", "CAPA capability analysis (*.json) results allow XRefer to further enrich the function contexts with semantic behaviour descriptions."),
            "xrefs": (
                "User XRefs File Missing",
                "Addresses of indirect call targets (e.g., C++ virtual functions, function "
                "pointers) can be provided to XRefer to build complete call paths where "
                "static analysis alone cannot determine the target. This is particularly "
                "useful for C++ binaries using virtual dispatch or callback-based designs.",
            ),
        }

        first = True
        for file_type in self.missing_files:
            if file_type in descriptions:
                if not first:
                    separator = QFrame()
                    separator.setFrameShape(QFrame.HLine)
                    separator.setFrameShadow(QFrame.Sunken)
                    frame_layout.addWidget(separator)
                first = False

                container = QWidget()
                container_layout = QVBoxLayout(container)
                container_layout.setSpacing(5)
                container_layout.setContentsMargins(0, 0, 0, 0)

                title, desc = descriptions[file_type]

                # Title
                title_label = QLabel(f"<b>{title}</b>")
                title_label.setFont(QFont("Arial", 9))
                container_layout.addWidget(title_label)

                # Path
                path = self.missing_files[file_type]
                formatted_path = self.format_path(path)
                path_label = QLabel(f"Path: {formatted_path}")
                path_label.setFont(QFont("Arial", 9))
                path_label.setStyleSheet("color: #888888;")
                container_layout.addWidget(path_label)

                # Description
                desc_label = QLabel(desc)
                desc_label.setWordWrap(True)
                desc_label.setFont(QFont("Arial", 9))
                desc_label.setStyleSheet("color: #888888;")
                desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
                container_layout.addWidget(desc_label)

                frame_layout.addWidget(container)

        layout.addWidget(frame)
        layout.addSpacing(2)

        # Add note about proceeding
        note = QLabel("You can either cancel the current analysis to configure these files, or proceed with available data.")
        note.setWordWrap(True)
        note.setFont(QFont("Arial", 10))
        layout.addWidget(note)

        # Set the content widget to scroll area
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

        # Add buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        cancel_button = QPushButton("Cancel Analysis")
        cancel_button.setMinimumWidth(120)
        cancel_button.clicked.connect(self.reject)

        proceed_button = QPushButton("Proceed Anyway")
        proceed_button.setMinimumWidth(120)
        proceed_button.clicked.connect(self.accept)

        button_layout.addStretch()
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(proceed_button)
        main_layout.addLayout(button_layout)

        # Let the dialog size itself based on content
        self.adjustSize()
