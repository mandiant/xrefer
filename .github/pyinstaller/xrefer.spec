# -*- mode: python ; coding: utf-8 -*-
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
#
# PyInstaller spec for the standalone xrefer binary — one-file console
# executable with the vivisect backend (the only backend that can be
# fully bundled: IDA/Binary Ninja/Ghidra need a host application/JVM on
# the target machine). Modeled on capa's
# .github/pyinstaller/pyinstaller.spec.
#
# Build (from this directory, in a venv where the xrefer wheel is
# installed — build against the wheel so the binary ships exactly what
# pip users get):
#     pip install /path/to/dist/xrefer-*.whl[vivisect] pyinstaller
#     pyinstaller xrefer.spec --noconfirm
# Output: dist/xrefer (ELF/Mach-O) or dist/xrefer.exe (Windows).
# PyInstaller cannot cross-compile — each OS builds its own binary (CI
# matrix, same as capa).

import importlib.util
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Build against the *installed* xrefer package.
xrefer_root = Path(importlib.util.find_spec("xrefer").origin).parent

datas = [
    # analyzer.generate_html_report resolves the report template via
    # Path(__file__).parent.parent / "data" -> the bundle must place it
    # at xrefer/data for the frozen __file__ layout to line up.
    (str(xrefer_root / "data"), "xrefer/data"),
]
# Packages that read their own data files at runtime:
#  - litellm: model-cost/provider JSONs
#  - tiktoken/tiktoken_ext: tokenizer encodings
#  - dspy: signature/template resources
#  - capa: rules metadata helpers
for pkg in ("litellm", "dspy", "tiktoken", "tiktoken_ext", "capa"):
    try:
        datas += collect_data_files(pkg)
    except Exception:
        pass

# GUI/Qt trees are excluded below; keep them out of hiddenimports too so
# PyInstaller does not log "hidden import not found" errors for modules
# we deliberately drop (vivisect ships vqt/envi.qt GUI helpers that pull
# PyQt5).
_QT_PREFIXES = ("vqt", "envi.qt", "vdb.qt", "vdb.gui")

hiddenimports = []
# vivisect discovers analysis passes dynamically (vivisect.analysis.*,
# envi.archs.*) — invisible to PyInstaller's static import analysis.
for pkg in ("vivisect", "envi", "vstruct", "PE", "Elf", "vtrace", "tiktoken_ext"):
    try:
        hiddenimports += [m for m in collect_submodules(pkg) if not m.startswith(_QT_PREFIXES)]
    except Exception:
        pass

excludes = [
    # GUI toolkits (vivisect's vqt/vdb GUI pulls these when present)
    "tkinter",
    "_tkinter",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "qtpy",
    "vqt",
    "vdb.qt",
    "envi.qt",
    # Disassembler hosts that cannot be bundled (the idapro PyPI shim
    # would only advertise a backend that cannot work standalone).
    "idapro",
    "ida_hcli",
    "pyghidra",
    "binaryninja",
    # dev/test-only
    "pytest",
    "IPython",
    "matplotlib",
]

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="xrefer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)
