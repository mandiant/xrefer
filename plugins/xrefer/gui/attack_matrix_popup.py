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

"""ATT&CK Navigator-style heat-grid popup for the cluster MITRE mappings.

The TUI ``attack_matrix`` mode (see ``gui/view.py::draw_attack_matrix``) is
the working surface — navigable, cross-linked to clusters, text-only. This
is its visual companion: a true 2-D grid the 85-column custom viewer can't
render — tactics as columns (kill-chain order), techniques stacked beneath
each as cells, every cell shaded by how many clusters exhibit the technique
(the "heat"). Glanceable / screenshot-ready; read-only by design (a modal
dialog can't drive the underlying IDA view, so cells link out to MITRE
rather than into clusters).

Takes an already-computed :class:`xrefer.core.mitre.MitreMatrix`, so no LLM
call and no disassembler state here. GUI layer (Qt via qtpy), imported
lazily so headless / core code never pulls Qt. Reuses the settings dialog's
palette-aware stylesheet and the token-estimate dialog's palette/blend
helpers so it matches the rest of xrefer's UI and the active IDA theme.
"""

import html
from typing import List, Optional

from qtpy import QtCore, QtGui, QtWidgets

from xrefer.gui.token_estimate import _blend, _ida_main_window, _palette

# Cell / column geometry.
_COL_W = 98
_CELL_H = 28
_GRID_SPACING = 10   # px between tactic columns
_COL_SPACING = 5     # px between cells within a column
# Vertical-size estimates (px) used to auto-size the dialog. Over-estimates
# only leave a little slack; under-estimates fall back to the scroll area.
_HEADER_EST = 44     # wrapping tactic header (up to ~3 lines) + slack
_BADGE_EST = 18      # per-column count badge row
_V_CHROME = 264      # title/subtitle/note/legend/footer + spacings + separator + buttons + margins
# Heat blend weights toward the accent (1.0 = pure accent). Coolest cell sits
# at _HEAT_LO, hottest at _HEAT_HI; single-coverage matrices use _HEAT_MID.
_HEAT_LO = 0.34
_HEAT_HI = 0.96
_HEAT_MID = 0.6


def _text_for(fill: QtGui.QColor) -> QtGui.QColor:
    """High-contrast text color for a given cell fill (luminance pick)."""
    lum = 0.299 * fill.red() + 0.587 * fill.green() + 0.114 * fill.blue()
    return QtGui.QColor(24, 24, 24) if lum > 150 else QtGui.QColor(244, 244, 244)


class _HeatCell(QtWidgets.QWidget):
    """One technique: a rounded, heat-filled cell showing its id. Hover for
    the name / rationale / grounding clusters; click to open its MITRE page."""

    def __init__(self, technique, fill: QtGui.QColor, muted_hex: str, parent=None):
        super().__init__(parent)
        self._id = technique.id
        self._fill = fill
        self._text = _text_for(fill)
        self._url = technique.url
        self.setFixedHeight(_CELL_H)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        if self._url:
            self.setCursor(QtCore.Qt.PointingHandCursor)

        tip = f"<b>{html.escape(technique.id)}</b>"
        if technique.name:
            tip += f" — {html.escape(technique.name)}"
        tip += f'<br><span style="color:{muted_hex};">{html.escape(technique.tactic)}</span>'
        if technique.representative_rationale:
            tip += f"<br>{html.escape(technique.representative_rationale)}"
        if technique.cluster_ids:
            chips = ", ".join(f"cluster.id.{cid:04d}" for cid in technique.cluster_ids)
            tip += f'<br><span style="color:{muted_hex};">{html.escape(chips)}</span>'
        if self._url:
            tip += f'<br><span style="color:{muted_hex};">click → {html.escape(self._url)}</span>'
        self.setToolTip(tip)

    def paintEvent(self, _ev) -> None:
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        r = QtCore.QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)
        path = QtGui.QPainterPath()
        path.addRoundedRect(r, 5.0, 5.0)
        p.fillPath(path, self._fill)
        p.setPen(QtGui.QPen(_blend(self._text, self._fill, 0.22), 1.0))
        p.drawRoundedRect(r, 5.0, 5.0)
        p.setPen(self._text)
        f = p.font()
        f.setBold(True)
        f.setPointSizeF(max(7.5, f.pointSizeF() * 0.95))
        p.setFont(f)
        p.drawText(r, QtCore.Qt.AlignCenter, self._id)
        p.end()

    def mousePressEvent(self, ev) -> None:
        if self._url and ev.button() == QtCore.Qt.LeftButton:
            try:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(self._url))
            except Exception:
                pass


def _heat_fill(cluster_count: int, max_count: int,
               accent: QtGui.QColor, window: QtGui.QColor) -> QtGui.QColor:
    """Blend the accent toward the window by coverage: more clusters → more
    saturated. Returns the cell fill color."""
    if max_count <= 1:
        weight = _HEAT_MID
    else:
        frac = (cluster_count - 1) / (max_count - 1)
        weight = _HEAT_LO + (_HEAT_HI - _HEAT_LO) * max(0.0, min(1.0, frac))
    return _blend(accent, window, weight)


def _swatch(color: QtGui.QColor) -> QtWidgets.QLabel:
    lbl = QtWidgets.QLabel()
    lbl.setFixedSize(18, 12)
    lbl.setStyleSheet(f"background:{color.name()}; border-radius:3px;")
    return lbl


def _build_legend(max_count: int, accent: QtGui.QColor, window: QtGui.QColor,
                  muted: str) -> QtWidgets.QWidget:
    w = QtWidgets.QWidget()
    lay = QtWidgets.QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    lo = QtWidgets.QLabel("1 cluster")
    lo.setStyleSheet(f"color:{muted}; font-size:8pt;")
    lay.addWidget(lo)
    steps = 5
    for i in range(steps):
        frac = i / (steps - 1)
        weight = _HEAT_LO + (_HEAT_HI - _HEAT_LO) * frac
        lay.addWidget(_swatch(_blend(accent, window, weight)))
    hi = QtWidgets.QLabel(f"{max(max_count, 1)} clusters" if max_count > 1 else "coverage")
    hi.setStyleSheet(f"color:{muted}; font-size:8pt;")
    lay.addWidget(hi)
    lay.addStretch(1)
    return w


def _build_column(group, max_count: int, accent: QtGui.QColor,
                  window: QtGui.QColor, muted: str) -> QtWidgets.QWidget:
    col = QtWidgets.QWidget()
    v = QtWidgets.QVBoxLayout(col)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(_COL_SPACING)

    head = QtWidgets.QLabel(group.tactic)
    head.setWordWrap(True)
    head.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
    head.setFixedWidth(_COL_W)
    head.setStyleSheet("font-weight:700; font-size:9pt;")
    v.addWidget(head)

    badge = QtWidgets.QLabel(str(len(group.techniques)))
    badge.setAlignment(QtCore.Qt.AlignHCenter)
    badge.setStyleSheet(f"color:{muted}; font-size:8pt;")
    v.addWidget(badge)

    for tech in group.techniques:
        fill = _heat_fill(tech.cluster_count, max_count, accent, window)
        cell = _HeatCell(tech, fill, muted)
        cell.setFixedWidth(_COL_W)
        v.addWidget(cell)

    v.addStretch(1)
    return col


def _add_export_controls(button_bar, dialog, matrix, base_name, title_suffix) -> None:
    """Add 'Copy ▾' (clipboard, per format) and 'Save…' (file, format chosen by
    the save-dialog filter) export buttons to the popup's bottom bar.

    The serialization itself lives in ``core/mitre.py`` (Navigator layer / STIX
    2.1 / CSV) — this is just clipboard + file IO and the menu wiring.
    """
    import json

    from xrefer.core.mitre import to_csv, to_navigator_layer, to_stix_bundle

    stem = (base_name or "attack-matrix").rsplit(".", 1)[0] or "attack-matrix"
    layer_name = f"{base_name} — xrefer ATT&CK matrix" if base_name else "xrefer ATT&CK matrix"
    if title_suffix:
        layer_name += f" ({title_suffix})"
    description = (
        f"ATT&CK techniques mapped by xrefer for {base_name}"
        if base_name else "ATT&CK techniques mapped by xrefer"
    )

    def _now_iso():
        # UTC ISO-8601 timestamp for the exported layer's metadata.
        try:
            from datetime import datetime, timezone
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except Exception:
            return None

    def _payload(fmt: str) -> str:
        if fmt == "navigator":
            return json.dumps(
                to_navigator_layer(matrix, name=layer_name, description=description), indent=2
            )
        if fmt == "stix":
            return json.dumps(to_stix_bundle(matrix, created=_now_iso(), name=layer_name), indent=2)
        return to_csv(matrix)

    def _toast(msg: str) -> None:
        try:
            QtWidgets.QToolTip.showText(QtGui.QCursor.pos(), msg)
        except Exception:
            pass

    def _copy(fmt: str, label: str) -> None:
        try:
            QtWidgets.QApplication.clipboard().setText(_payload(fmt))
            _toast(f"Copied {label} to clipboard")
        except Exception as exc:
            _toast(f"Copy failed: {exc}")

    def _save() -> None:
        filters = "ATT&CK Navigator layer (*.json);;STIX 2.1 bundle (*.json);;CSV (*.csv)"
        default = f"{stem}_attack_matrix.json"
        path, sel = QtWidgets.QFileDialog.getSaveFileName(
            dialog, "Export ATT&CK matrix", default, filters
        )
        if not path:
            return
        if "STIX" in sel:
            fmt, ext = "stix", ".json"
        elif "CSV" in sel:
            fmt, ext = "csv", ".csv"
        else:
            fmt, ext = "navigator", ".json"
        if not path.lower().endswith(ext):
            path += ext
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_payload(fmt))
            _toast(f"Saved → {path}")
        except Exception as exc:
            _toast(f"Save failed: {exc}")

    copy_btn = QtWidgets.QPushButton("Copy ▾")
    copy_menu = QtWidgets.QMenu(copy_btn)
    copy_menu.addAction("ATT&CK Navigator layer (JSON)", lambda: _copy("navigator", "Navigator layer"))
    copy_menu.addAction("STIX 2.1 bundle (JSON)", lambda: _copy("stix", "STIX bundle"))
    copy_menu.addAction("CSV", lambda: _copy("csv", "CSV"))
    # Pop the menu flush under the button on click. We deliberately do NOT use
    # setMenu(): its attached-menu indicator arrow renders detached at the far
    # right edge of the button (looks awkward); the inline ▾ in the label is the
    # affordance instead, and the button keeps the shared themed look.
    copy_btn.clicked.connect(
        lambda: copy_menu.exec_(copy_btn.mapToGlobal(QtCore.QPoint(0, copy_btn.height())))
    )
    button_bar.addWidget(copy_btn)

    save_btn = QtWidgets.QPushButton("Save…")
    save_btn.clicked.connect(_save)
    button_bar.addWidget(save_btn)


def show_attack_matrix_popup(matrix, title_suffix: Optional[str] = None,
                             base_name: Optional[str] = None, parent=None) -> None:
    """Display the ATT&CK heat-grid (modal) for an aggregated
    :class:`MitreMatrix`.

    ``title_suffix`` (e.g. ``"cluster.id.0012"``) marks a cluster-scoped
    matrix; ``None`` is the binary-wide matrix. ``base_name`` (the input file
    name) seeds the export filenames and the layer/bundle name.
    """
    from xrefer.gui.settings import _build_dialog_qss

    window_c, text_c, accent = _palette()
    muted = _blend(text_c, window_c, 0.6).name()
    soft = _blend(text_c, window_c, 0.82).name()

    if parent is None:
        parent = _ida_main_window()
    dialog = QtWidgets.QDialog(parent)
    dialog.setWindowTitle("ATT&CK Matrix" + (f" — {title_suffix}" if title_suffix else ""))
    dialog.setMinimumWidth(560)
    dialog.setStyleSheet(_build_dialog_qss())

    root = QtWidgets.QVBoxLayout(dialog)
    root.setContentsMargins(0, 0, 0, 0)
    root.setSpacing(0)

    content = QtWidgets.QWidget()
    c = QtWidgets.QVBoxLayout(content)
    c.setContentsMargins(22, 20, 22, 14)
    c.setSpacing(10)

    # Title + subtitle.
    heading = "ATT&CK Matrix"
    if title_suffix:
        heading += f" — {title_suffix}"
    title = QtWidgets.QLabel(f'<span style="font-size:13pt; font-weight:700;">{html.escape(heading)}</span>')
    title.setTextFormat(QtCore.Qt.RichText)
    c.addWidget(title)

    if title_suffix:
        sub = f"{matrix.technique_count} technique(s) across {matrix.tactic_count} tactic(s)"
    else:
        sub = (
            f"{matrix.technique_count} techniques across {matrix.tactic_count} tactics · "
            f"grounded in {matrix.clusters_with_techniques} of {matrix.total_clusters} clusters"
        )
    sub_lbl = QtWidgets.QLabel(f'<span style="color:{soft}; font-size:9pt;">{html.escape(sub)}</span>')
    sub_lbl.setTextFormat(QtCore.Qt.RichText)
    c.addWidget(sub_lbl)

    if matrix.is_empty:
        empty = QtWidgets.QLabel(
            f'<span style="color:{muted};">No MITRE ATT&amp;CK techniques were mapped '
            "for these clusters.</span>"
        )
        empty.setTextFormat(QtCore.Qt.RichText)
        empty.setWordWrap(True)
        c.addWidget(empty)
    else:
        max_count = max((t.cluster_count for g in matrix.tactics for t in g.techniques), default=1)

        note = QtWidgets.QLabel(
            f'<span style="color:{muted}; font-size:9pt;">Cells shaded by how many '
            "clusters exhibit each technique · hover for detail · click to open MITRE</span>"
        )
        note.setTextFormat(QtCore.Qt.RichText)
        note.setWordWrap(True)
        c.addWidget(note)
        c.addWidget(_build_legend(max_count, accent, window_c, muted))

        # The grid: one column per (covered) tactic, kill-chain order.
        grid_host = QtWidgets.QWidget()
        grid = QtWidgets.QHBoxLayout(grid_host)
        grid.setContentsMargins(0, 6, 0, 0)
        grid.setSpacing(_GRID_SPACING)
        # Centre the columns so the dialog's left/right padding stays symmetric
        # when the grid is narrower than the window. (Do NOT add a trailing
        # stretch: it packs the columns left and dumps all the slack on the
        # right — the cause of the lopsided padding.) When the grid is wider
        # than the viewport it simply overflows and scrolls, anchored at the
        # first column, which is the natural reading order.
        grid.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
        for group in matrix.tactics:
            grid.addWidget(_build_column(group, max_count, accent, window_c, muted))

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll.setWidget(grid_host)
        scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        c.addWidget(scroll, 1)

        # Uncovered tactics note (binary-wide only — keeps the kill-chain gaps
        # visible even though empty tactics get no column).
        if not title_suffix and matrix.uncovered_tactics:
            unc = QtWidgets.QLabel(
                f'<span style="color:{muted}; font-size:8pt;">Not observed: '
                f'{html.escape(", ".join(matrix.uncovered_tactics))}</span>'
            )
            unc.setTextFormat(QtCore.Qt.RichText)
            unc.setWordWrap(True)
            c.addWidget(unc)

    root.addWidget(content, 1)

    # Separator + bottom button bar (matches the About / Settings / estimate dialogs).
    sep = QtWidgets.QFrame()
    sep.setFrameShape(QtWidgets.QFrame.HLine)
    sep.setProperty("separator", True)
    root.addWidget(sep)

    button_bar = QtWidgets.QHBoxLayout()
    button_bar.setContentsMargins(16, 12, 16, 16)
    button_bar.setSpacing(8)
    if not matrix.is_empty:
        _add_export_controls(button_bar, dialog, matrix, base_name, title_suffix)
    button_bar.addStretch()
    close_button = QtWidgets.QPushButton("Close")
    close_button.setProperty("primary", True)
    close_button.setDefault(True)
    close_button.clicked.connect(dialog.accept)
    button_bar.addWidget(close_button)
    root.addLayout(button_bar)

    # ---- Auto-size to the grid, bounded by the screen ------------------
    # The dialog's width tracks the real matrix width (one column per covered
    # tactic) so every column is visible without horizontal scrolling — until
    # that would exceed the available screen (minus padding), at which point
    # it's clamped and the grid scrolls. A QScrollArea reports only a tiny
    # size hint, so adjustSize() can't do this; we size from the geometry.
    screen = QtWidgets.QApplication.primaryScreen().availableGeometry()
    screen_pad = 48
    max_w = max(560, screen.width() - screen_pad)
    max_h = int(screen.height() * 0.9)

    n_cols = len(matrix.tactics)
    if n_cols:
        tallest = max((len(g.techniques) for g in matrix.tactics), default=0)
        grid_w = n_cols * _COL_W + (n_cols - 1) * _GRID_SPACING
        grid_h = _HEADER_EST + _BADGE_EST + tallest * (_CELL_H + _COL_SPACING)
        desired_h = grid_h + _V_CHROME
        # Horizontal chrome = content L/R margins (22+22). Reserve the vertical
        # scrollbar's width ONLY when the grid will actually scroll (its height
        # gets clamped) — reserving it unconditionally just became dead space on
        # the right. The grid is centred (see the grid layout), so any residual
        # width splits evenly L/R. Scrollbar is 10px + 2px margins per the QSS.
        scrollbar_w = 14 if desired_h > max_h else 0
        desired_w = grid_w + (22 + 22) + scrollbar_w
    else:
        # Empty matrix — just the message; keep the comfortable minimum.
        desired_w, desired_h = 560, 320

    final_w = max(560, min(desired_w, max_w))
    final_h = max(320, min(desired_h, max_h))

    dialog.setMaximumSize(max_w, max_h)
    dialog.resize(final_w, final_h)

    frame_geom = dialog.frameGeometry()
    frame_geom.moveCenter(screen.center())
    dialog.move(frame_geom.topLeft())

    dialog.exec_()
