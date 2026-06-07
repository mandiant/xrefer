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

"""On-demand "will this fit?" token-budget visual for cluster analysis.

Renders a ``TokenEstimate`` (from ``ClusterAnalyzer.estimate_cluster_request``)
as a segmented budget bar — request tokens + max response tokens stacked
against the configured model's context window — with a 95% threshold marker
and a warning banner when the projected total approaches or exceeds the
window. Pure presentation: no LLM call, no disassembler state; the numbers
are computed upstream.

GUI layer (Qt via qtpy), imported lazily from the action handler so headless
/ core code never pulls Qt. Reuses the settings dialog's palette-aware
stylesheet (``_build_dialog_qss``) so it inherits whatever IDA theme is
active; the bar itself is custom-painted from the live palette.
"""

from typing import List, Optional

from qtpy import QtCore, QtGui, QtWidgets

# Fraction of the context window at/above which we warn. Mirrors
# TokenEstimate.warn so the bar's amber zone and the banner agree.
WARN_THRESHOLD = 0.95


def _palette():
    pal = QtWidgets.QApplication.palette()
    return (
        pal.color(QtGui.QPalette.Window),
        pal.color(QtGui.QPalette.WindowText),
        pal.color(QtGui.QPalette.Highlight),
    )


def _blend(c1: QtGui.QColor, c2: QtGui.QColor, w: float) -> QtGui.QColor:
    """Blend two colors: w=1.0 is ``c1`` entirely, w=0.0 is ``c2``."""
    return QtGui.QColor(
        int(c1.red() * w + c2.red() * (1 - w)),
        int(c1.green() * w + c2.green() * (1 - w)),
        int(c1.blue() * w + c2.blue() * (1 - w)),
    )


def _ida_main_window():
    """Best-effort handle to IDA's top-level main window so dialogs can be
    parented to it. Without a parent, ``exec_()`` doesn't reliably take key
    focus away from IDA's native custom-view (the xrefer view), which then
    keeps receiving OnKeydown — stealing e.g. arrow keys from a combo's
    completer popup. Returns None if it can't be found (dialog stays
    parentless, same as before)."""
    try:
        app = QtWidgets.QApplication.instance()
        if app is None:
            return None
        for w in app.topLevelWidgets():
            if isinstance(w, QtWidgets.QMainWindow) and w.windowTitle().startswith("IDA"):
                return w
        return app.activeWindow()
    except Exception:
        return None


# Fixed warn/danger hues, blended toward the host window color at paint
# time so they harmonize with dark or light themes without us guessing a
# theme-specific red.
_AMBER = QtGui.QColor(0xF5, 0xA5, 0x24)
_RED = QtGui.QColor(0xE5, 0x48, 0x4D)


class _BudgetBar(QtWidgets.QWidget):
    """Custom-painted horizontal budget bar.

    The full track represents the model's context window. A filled accent
    segment shows request tokens; a lighter segment stacked after it shows
    the max response tokens. A dashed tick at ``WARN_THRESHOLD`` marks the
    warn line. When the stacked total approaches the window the fill turns
    amber, and when it exceeds the window the fill clamps to full width,
    recolors red, and grows a hatched overflow cap on the trailing edge.

    With an unknown window (window <= 0) only the empty track is drawn —
    the numeric breakdown carries the "unknown" message in that case.
    """

    def __init__(self, request: int, response: int, window: int, parent=None):
        super().__init__(parent)
        self._request = max(0, int(request or 0))
        self._response = max(0, int(response or 0))
        self._window = int(window) if window else 0
        self.setMinimumHeight(34)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

    def paintEvent(self, _ev) -> None:
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)

        win_c, text_c, accent = _palette()
        radius = 8.0
        rect = QtCore.QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)

        track = _blend(text_c, win_c, 0.12)
        track_border = _blend(text_c, win_c, 0.28)

        clip = QtGui.QPainterPath()
        clip.addRoundedRect(rect, radius, radius)
        painter.fillPath(clip, track)

        if self._window > 0:
            req_frac = self._request / self._window
            tot_frac = (self._request + self._response) / self._window
            over = tot_frac > 1.0
            warn = tot_frac >= WARN_THRESHOLD

            if over:
                req_color, resp_color = _RED, _blend(_RED, win_c, 0.55)
            elif warn:
                req_color, resp_color = _AMBER, _blend(_AMBER, win_c, 0.5)
            else:
                req_color, resp_color = QtGui.QColor(accent), _blend(accent, win_c, 0.5)

            painter.save()
            painter.setClipPath(clip)
            full_w = rect.width()
            req_w = full_w * min(req_frac, 1.0)
            tot_w = full_w * min(tot_frac, 1.0)
            painter.fillRect(
                QtCore.QRectF(rect.left(), rect.top(), req_w, rect.height()), req_color
            )
            if tot_w > req_w:
                painter.fillRect(
                    QtCore.QRectF(rect.left() + req_w, rect.top(), tot_w - req_w, rect.height()),
                    resp_color,
                )
            if over:
                cap_w = min(16.0, full_w * 0.06)
                hatch = QtGui.QBrush(_blend(QtGui.QColor(255, 255, 255), _RED, 0.4), QtCore.Qt.BDiagPattern)
                painter.fillRect(
                    QtCore.QRectF(rect.right() - cap_w, rect.top(), cap_w, rect.height()), hatch
                )
            painter.restore()

            # 95% threshold tick.
            tick_x = rect.left() + full_w * WARN_THRESHOLD
            painter.setPen(QtGui.QPen(_blend(text_c, win_c, 0.7), 1.2, QtCore.Qt.DashLine))
            painter.drawLine(
                QtCore.QPointF(tick_x, rect.top() + 3), QtCore.QPointF(tick_x, rect.bottom() - 3)
            )

        painter.setPen(QtGui.QPen(track_border, 1.0))
        painter.setBrush(QtCore.Qt.NoBrush)
        painter.drawRoundedRect(rect, radius, radius)
        painter.end()


def _dot(color_hex: str, label: str, label_hex: str) -> str:
    return (
        f'<span style="color:{color_hex}; font-size:13pt;">&#9679;</span>'
        f'<span style="color:{label_hex};"> {label}</span>'
    )


def _maybe_banner(util: Optional[float], total: int, window_tokens: int,
                  window_c: QtGui.QColor, text_c: QtGui.QColor,
                  blocked: bool = False) -> Optional[QtWidgets.QFrame]:
    """Build the colored warning/danger banner, or None when usage is
    comfortably under the threshold (or the window is unknown).

    ``blocked`` forces a red 'request was NOT sent' banner — used when the
    run-time gate skipped the LLM call for exceeding the context window.
    """
    # U+26A0 renders in base fonts on every platform (unlike emoji-block
    # glyphs); severity is carried by the red vs amber tint + wording.
    icon = "⚠"
    if blocked:
        tint = _RED
        msg = (
            "The cluster-analysis request was NOT sent to the LLM — its estimated "
            f"{total:,} tokens exceed the {window_tokens:,}-token context window. Pick a "
            "model with a larger context window (or reduce the analyzed scope) and re-run."
        )
    elif util is None or util < WARN_THRESHOLD:
        return None
    elif util > 1.0:
        tint = _RED
        msg = (
            f"Estimated request + response ({total:,} tok) exceeds the model's "
            f"{window_tokens:,}-token context window. This request will likely be "
            "rejected. Use a model with a larger context window."
        )
    else:
        tint = _AMBER
        msg = (
            f"Estimated usage is {util * 100:.0f}% of the model's "
            f"{window_tokens:,}-token context window. The request may be rejected or "
            "its response truncated. Consider a larger-context model."
        )

    frame = QtWidgets.QFrame()
    frame.setStyleSheet(
        f"QFrame {{ background: {_blend(tint, window_c, 0.16).name()}; "
        f"border: 1px solid {_blend(tint, window_c, 0.5).name()}; border-radius: 6px; }}"
    )
    lay = QtWidgets.QHBoxLayout(frame)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.setSpacing(0)
    label = QtWidgets.QLabel(
        f'<span style="font-size:12pt; color:{tint.name()};">{icon}</span>&nbsp;&nbsp;'
        f'<span style="color:{text_c.name()};">{msg}</span>'
    )
    label.setWordWrap(True)
    label.setTextFormat(QtCore.Qt.RichText)
    lay.addWidget(label)
    return frame


def _clear_layout(layout) -> None:
    """Remove and delete every item in a layout — used to re-render the
    estimate body in place when the model dropdown changes."""
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)
            w.deleteLater()
        else:
            child = item.layout()
            if child is not None:
                _clear_layout(child)


def _populate_estimate_body(layout, estimate, window_c, text_c, accent,
                            muted, soft, accent_hex, resp_hex, blocked) -> None:
    """(Re)build the dynamic part of the dialog — bar, legend, breakdown,
    banner, notes — into ``layout`` for ``estimate``. Called on open and again
    on every model-dropdown change."""
    req = int(estimate.request_tokens or 0)
    resp = int(estimate.max_response_tokens or 0)
    total = req + resp
    window_tokens = int(estimate.context_window or 0)
    util = (total / window_tokens) if window_tokens else None

    layout.addWidget(_BudgetBar(req, resp, window_tokens))

    win_txt = f"{window_tokens:,} tok" if window_tokens else "unknown"
    legend = QtWidgets.QLabel(
        '<div>'
        + _dot(accent_hex, f"Request {req:,}", soft)
        + "&nbsp;&nbsp;&nbsp;&nbsp;"
        + _dot(resp_hex, f"Max response {resp:,}", soft)
        + f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:{muted};">Context window {win_txt}</span>'
        + '</div>'
    )
    legend.setTextFormat(QtCore.Qt.RichText)
    layout.addWidget(legend)

    if util is not None:
        if util > 1.0:
            util_hex = _RED.name()
        elif util >= WARN_THRESHOLD:
            util_hex = _AMBER.name()
        else:
            util_hex = soft
        breakdown = QtWidgets.QLabel(
            '<div style="font-size:10pt;">Projected total '
            f'<span style="font-weight:700;">{total:,}</span> tok&nbsp;/&nbsp;{window_tokens:,} tok '
            f'(<span style="color:{util_hex}; font-weight:700;">{util * 100:.0f}%</span> of context window)'
            '</div>'
        )
    else:
        breakdown = QtWidgets.QLabel(
            f'<div style="font-size:10pt; color:{muted};">Projected total '
            f'<span style="font-weight:700; color:{soft};">{total:,}</span> tok '
            '(context window unknown for this model)</div>'
        )
    breakdown.setTextFormat(QtCore.Qt.RichText)
    layout.addWidget(breakdown)

    banner = _maybe_banner(util, total, window_tokens, window_c, text_c, blocked=blocked)
    if banner is not None:
        layout.addWidget(banner)

    mode = getattr(estimate, "mode", "full")
    notes: List[str] = []
    if mode == "hierarchical":
        notes.append(
            "Hierarchical (bottom-up) mode: child clusters are sent as short "
            "summaries, so each call carries one cluster's own detail plus a few "
            f"child summaries. About {estimate.num_calls} call(s); the bar sizes "
            "the largest single call — the binding fit constraint."
        )
        rnc = getattr(estimate, "run_num_ctx", None)
        if rnc:
            notes.append(
                f"Local context (num_ctx) capped at {rnc:,} tok for this run — this "
                "bounds Ollama's KV-cache memory, decoupled from the model's "
                "advertised window."
            )
    else:
        groups = getattr(estimate, "num_closures", 1)
        notes.append(
            f"Clusters split into {groups} independent group(s); about "
            f"{estimate.num_calls} call(s), one group per call. The bar sizes the "
            "largest group — the binding fit constraint."
        )
    if getattr(estimate, "response_capped", False):
        notes.append(
            "Max response is capped for this estimate — this model advertises a far "
            "larger output cap we'd never use for cluster analysis."
        )
    if not estimate.rendered:
        notes.append(
            "Counted the cluster payload only (prompt scaffolding excluded); the real "
            "request is somewhat larger."
        )
    if estimate.note:
        notes.append(estimate.note)
    note_label = QtWidgets.QLabel(
        f'<div style="font-size:9pt; color:{muted};">'
        + "<br>".join("• " + n for n in notes)
        + '</div>'
    )
    note_label.setWordWrap(True)
    note_label.setTextFormat(QtCore.Qt.RichText)
    layout.addWidget(note_label)


def show_token_estimate_dialog(estimate, parent=None, blocked: bool = False,
                               recompute=None, models=None, current_model=None) -> None:
    """Display the budget-bar dialog for a ``TokenEstimate`` (modal).

    ``blocked`` switches to 'analysis blocked' framing — title + a red
    'request was NOT sent' banner — for the run-time gate's overflow case.

    When ``recompute`` (``model_id -> TokenEstimate``) and ``models`` (model
    ids) are supplied and not ``blocked``, a model dropdown is shown; changing
    it re-renders the bar/numbers live for that model.
    """
    from xrefer.gui.settings import _build_dialog_qss, make_combo_searchable

    heading = "Cluster Analysis Blocked" if blocked else "Cluster Analysis Token Estimate"
    window_c, text_c, accent = _palette()
    muted = _blend(text_c, window_c, 0.6).name()
    soft = _blend(text_c, window_c, 0.82).name()
    accent_hex = QtGui.QColor(accent).name()
    resp_hex = _blend(accent, window_c, 0.5).name()

    if parent is None:
        parent = _ida_main_window()
    dialog = QtWidgets.QDialog(parent)
    dialog.setWindowTitle("Cluster Analysis — " + ("Blocked" if blocked else "Token Estimate"))
    dialog.setMinimumWidth(560)
    dialog.setStyleSheet(_build_dialog_qss())

    root = QtWidgets.QVBoxLayout(dialog)
    root.setContentsMargins(0, 0, 0, 0)
    root.setSpacing(0)

    content_widget = QtWidgets.QWidget()
    content = QtWidgets.QVBoxLayout(content_widget)
    content.setContentsMargins(22, 20, 22, 14)
    content.setSpacing(12)

    # Title.
    title = QtWidgets.QLabel(f'<span style="font-size:13pt; font-weight:700;">{heading}</span>')
    title.setTextFormat(QtCore.Qt.RichText)
    content.addWidget(title)

    use_dropdown = bool(recompute and models and not blocked)
    if use_dropdown:
        # Model selector. The combo inherits the settings-dialog QSS (accent
        # border + custom chevron), so it matches the rest of xrefer's UI.
        row = QtWidgets.QHBoxLayout()
        row.setSpacing(8)
        row_lbl = QtWidgets.QLabel("Model")
        row_lbl.setStyleSheet(f"color:{muted}; font-size:9pt;")
        combo = QtWidgets.QComboBox()
        combo.addItems(list(models))
        make_combo_searchable(combo)  # type-to-filter over the long model list
        sel = current_model or estimate.model_id
        if sel and sel in models:
            combo.setCurrentText(sel)
        combo.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        row.addWidget(row_lbl)
        row.addWidget(combo, 1)
        content.addLayout(row)
    else:
        model_name = estimate.model_id or "No model configured"
        model_lbl = QtWidgets.QLabel(
            f'<span style="color:{muted}; font-size:9pt;">Model: {model_name}</span>'
        )
        model_lbl.setTextFormat(QtCore.Qt.RichText)
        content.addWidget(model_lbl)

    # Dynamic content, re-rendered on model change.
    dyn_widget = QtWidgets.QWidget()
    dyn = QtWidgets.QVBoxLayout(dyn_widget)
    dyn.setContentsMargins(0, 0, 0, 0)
    dyn.setSpacing(12)
    content.addWidget(dyn_widget)

    def render(est) -> None:
        _clear_layout(dyn)
        _populate_estimate_body(dyn, est, window_c, text_c, accent,
                                muted, soft, accent_hex, resp_hex, blocked)
        dialog.adjustSize()

    render(estimate)

    if use_dropdown:
        last_model = {"v": current_model}

        def _maybe_recompute() -> None:
            model_id = combo.currentText().strip()
            if not model_id or model_id == last_model["v"]:
                return
            last_model["v"] = model_id
            try:
                new_est = recompute(model_id)
            except Exception as exc:
                log(f"[-] Error recomputing estimate for {model_id}: {exc}")
                return
            render(new_est)

        # Recompute on an explicit pick (dropdown click), when the search
        # field's editing finishes (Enter / focus-out — also covers a typed
        # custom id), and on a completer pick where the binding exposes it.
        # The last_model guard dedupes these overlapping signals.
        combo.activated.connect(lambda _idx: _maybe_recompute())
        line = combo.lineEdit()
        if line is not None:
            line.editingFinished.connect(_maybe_recompute)
        try:
            combo.completer().activated[str].connect(lambda _t: _maybe_recompute())
        except Exception:
            pass
        # Give the search field initial focus so typing / arrow keys go to it
        # (and its completer) rather than the view behind the dialog.
        combo.setFocus()

    root.addWidget(content_widget, 1)

    # Separator + bottom button bar (matches the About / Settings dialogs).
    sep = QtWidgets.QFrame()
    sep.setFrameShape(QtWidgets.QFrame.HLine)
    sep.setProperty("separator", True)
    root.addWidget(sep)

    button_bar = QtWidgets.QHBoxLayout()
    button_bar.setContentsMargins(16, 12, 16, 16)
    button_bar.addStretch()
    close_button = QtWidgets.QPushButton("Close")
    close_button.setProperty("primary", True)
    close_button.setDefault(True)
    close_button.clicked.connect(dialog.accept)
    button_bar.addWidget(close_button)
    root.addLayout(button_bar)

    # Center on screen.
    frame_geom = dialog.frameGeometry()
    frame_geom.moveCenter(QtWidgets.QApplication.primaryScreen().availableGeometry().center())
    dialog.move(frame_geom.topLeft())

    dialog.exec_()


def show_budget_block_if_pending(xrefer_obj) -> None:
    """If the last cluster analysis was skipped for exceeding the model's
    context window, show the budget bar (blocked framing) and clear the
    flag. No-op otherwise. Defensive — never raises into the caller, so it
    can sit at the tail of view creation / handler flows safely.
    """
    try:
        if xrefer_obj is None:
            return
        estimate = getattr(xrefer_obj, "cluster_token_budget_exceeded", None)
        if not estimate:
            return
        # Clear first so a later trigger (e.g. a view refresh) can't re-show it.
        xrefer_obj.cluster_token_budget_exceeded = None
        show_token_estimate_dialog(estimate, blocked=True)
    except Exception as exc:
        try:
            log(f"[-] Error showing token-budget block dialog: {exc}")
        except Exception:
            pass
