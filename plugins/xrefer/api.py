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

"""
Programmatic entry point for XRefer.

The CLI (``xrefer`` / ``python -m xrefer``) and this module share the
same per-backend analysis drivers in :mod:`xrefer.cli`; ``analyze()`` is
the library-consumer surface::

    import xrefer

    result = xrefer.analyze("/path/to/binary", backend="vivisect", llm=False)
    print(result.lang.entry_point)

Returns the fully-populated ``XRefer`` analyzer object (call paths,
clusters, artifacts). Report files are NOT written by default —
programmatic callers usually want the object, not files; pass
``report="html"`` (or ``"json"``) to also emit the report next to the
binary.
"""

from pathlib import Path
from typing import Any, Literal, Optional

ReportMode = Literal["html", "json", "none"]


def available_backends() -> list[str]:
    """Names of analysis backends usable on this machine right now."""
    from xrefer.cli import detect_available_backends

    return detect_available_backends()


def analyze(
    file_path: str | Path,
    backend: Optional[str] = None,
    *,
    mode: Literal["light", "full"] = "light",
    report: ReportMode = "none",
    llm: Optional[bool] = None,
    auto_analysis: bool = True,
    save: bool = False,
    force: bool = False,
    entry_point: Optional[int] = None,
    output: Optional[str | Path] = None,
    settings_overrides: Optional[dict[str, Any]] = None,
):
    """Analyze a binary and return the populated ``XRefer`` object.

    Args:
        file_path: Binary to analyze.
        backend: ``"ida"`` / ``"binaryninja"`` / ``"ghidra"`` /
            ``"vivisect"``. ``None`` auto-selects the first available in
            that order (vivisect ships with the package, so there is
            always a fallback).
        mode: ``"light"`` (default, report-equivalent but faster) or
            ``"full"`` (also builds the GUI-reusable cache).
        report: ``"none"`` (default), ``"html"`` or ``"json"`` — whether
            to also write a report file next to the binary.
        llm: Force-enable/disable LLM lookups for this run; ``None``
            defers to ``~/.xrefer/settings.json``.
        auto_analysis: Run the disassembler's auto-analysis on open.
        save: Persist backend database/project changes.
        force: Remove this backend's previous artifacts and re-analyze.
        entry_point: Override the entry-point address.
        output: Report output path (only meaningful with ``report=``).
        settings_overrides: Extra settings deep-merged over
            ``settings.json`` for this run (same shape the CLI builds
            from its flags).

    Raises:
        FileNotFoundError: ``file_path`` does not exist.
        ValueError: Unknown or unavailable ``backend``.
    """
    # cli.py is import-light (argparse/stdlib only at module level; the
    # heavy backend/disassembler imports all happen inside its
    # setup_*_backend functions), so importing it here keeps
    # ``import xrefer`` fast while sharing one set of drivers.
    from xrefer import cli as _cli

    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    detected = _cli.detect_available_backends()
    if backend is None:
        if not detected:
            raise ValueError("No analysis backends available (this should not happen: vivisect ships with xrefer)")
        backend = detected[0]
    elif backend not in ("ida", "binaryninja", "ghidra", "vivisect"):
        raise ValueError(f"Unknown backend: {backend!r}")
    elif backend not in detected:
        raise ValueError(f"Backend {backend!r} is not available on this machine (available: {', '.join(detected) or 'none'})")

    xrefer_kwargs: dict[str, Any] = {
        "auto_analyze": auto_analysis,
        "mode": mode,
        "report_data_mode": report,
    }
    if entry_point is not None:
        xrefer_kwargs["ep"] = entry_point
    overrides = dict(settings_overrides or {})
    if llm is not None:
        overrides["llm_lookups"] = llm
    if overrides:
        xrefer_kwargs["settings_overrides"] = overrides
    if output is not None:
        xrefer_kwargs["report_path"] = str(Path(output).resolve())

    # NOTE: each driver runs cleanup_previous_analysis(force) itself.
    drivers = {
        "ida": _cli._analyze_ida,
        "binaryninja": _cli._analyze_binaryninja,
        "ghidra": _cli._analyze_ghidra,
        "vivisect": _cli._analyze_vivisect,
    }
    return drivers[backend](path, auto_analysis, save, force, xrefer_kwargs=xrefer_kwargs)
