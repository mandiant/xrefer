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

"""Organize the IDA Functions window into library/user folders.

Consumes ``XRefer.compute_function_folders()`` (a backend-agnostic, origin
verdict computed in core) and applies it to IDA's native function dirtree via
``ida_dirtree``. This is the ONLY place ``ida_dirtree`` is touched: IDA APIs
are kept out of the backend-agnostic core, so all IDA-specific code lives in
the GUI layer.

Apply re-runs cleanly: it flattens xrefer's own roots (``_XREFER_ROOTS``)
first so every move originates from the tree root, and never disturbs folders
the user made by hand. "Remove All Folders" is deliberately broader — because
xrefer's roots are the generic names ``Library`` / ``User``, there's no
reliable way to tell xrefer's folders from identically-named user folders, so
the honest, practical reset flattens the entire function dirtree back to root.
"""

from typing import Dict, List, Tuple

import ida_dirtree

from xrefer.backend import Address
from xrefer.gui.helpers import log

# Top-level folders xrefer manages in the function dirtree.
_XREFER_ROOTS = ("Library", "User")


def _funcs_dirtree() -> "ida_dirtree.dirtree_t":
    return ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)


def _walk_dir(ft: "ida_dirtree.dirtree_t", dirpath: str,
              leaves: List[Tuple[str, str]], dirs: List[str]) -> None:
    """Recursively gather every leaf function and subfolder under the
    root-relative ``dirpath``, using only the dirtree iteration primitives
    (``chdir`` / ``findfirst`` / ``findnext`` / ``resolve_cursor`` /
    ``get_entry_name`` / ``isdir``) — the same ones the user's working revert
    snippet uses, extended to recurse into nested folders.

    All entry names in a folder are collected first, then classified, so the
    live iterator is never perturbed by interleaved ``isdir`` calls. ``leaves``
    accumulates ``(full_path, leaf_name)``; ``dirs`` accumulates folder paths
    (parents appended before their children).
    """
    dirs.append(dirpath)
    ft.chdir(dirpath)
    names: List[str] = []
    ite = ida_dirtree.dirtree_iterator_t()
    ok = ft.findfirst(ite, "*")
    while ok:
        de = ft.resolve_cursor(ite.cursor)
        # get_entry_name may return a path-qualified name; take the leaf, then
        # rebuild the full path from the known dirpath so we're robust to both.
        names.append(ft.get_entry_name(de).rsplit("/", 1)[-1])
        ok = ft.findnext(ite)
    ft.chdir("/")
    for nm in names:
        child = f"{dirpath}/{nm}"
        if ft.isdir(child):
            _walk_dir(ft, child, leaves, dirs)
        else:
            leaves.append((child, nm))


def _ensure_dir(ft: "ida_dirtree.dirtree_t", rel_path: str) -> None:
    """``mkdir`` each component of a root-relative ``/``-joined path, parents
    first. No-op for components that already exist."""
    parts = [p for p in rel_path.split("/") if p]
    cur = ""
    for p in parts:
        cur = f"{cur}/{p}" if cur else p
        if not ft.isdir(cur):
            ft.mkdir(cur)


def _top_level_dirs(ft: "ida_dirtree.dirtree_t") -> List[str]:
    """Return the names of every folder directly under the function-tree root.
    Names are collected before classification so the iterator isn't perturbed."""
    ft.chdir("/")
    names: List[str] = []
    ite = ida_dirtree.dirtree_iterator_t()
    ok = ft.findfirst(ite, "*")
    while ok:
        de = ft.resolve_cursor(ite.cursor)
        names.append(ft.get_entry_name(de).rsplit("/", 1)[-1])
        ok = ft.findnext(ite)
    return [nm for nm in names if ft.isdir(nm)]


def _flatten(ft: "ida_dirtree.dirtree_t", roots) -> int:
    """Move every function under each root folder back to the tree root, then
    delete the now-empty folders (deepest-first).

    Walks the tree with the standard dirtree iterator rather than guessing each
    function's path from its address — the same root-relative path primitives
    the apply path uses to create the folders. ``roots`` is the set of
    top-level folder names to flatten. Returns functions moved.
    """
    leaves: List[Tuple[str, str]] = []
    dirs: List[str] = []
    for root in roots:
        if ft.isdir(root):
            _walk_dir(ft, root, leaves, dirs)

    moved = 0
    for full_path, leaf in leaves:
        try:
            if ft.rename(full_path, leaf) == ida_dirtree.DTE_OK:
                moved += 1
        except Exception:
            pass
    # Deepest-first so each folder is empty by the time we remove it.
    for d in sorted(set(dirs), key=lambda p: p.count("/"), reverse=True):
        try:
            ft.rmdir(d)
        except Exception:
            pass
    return moved


def remove_all_folders() -> int:
    """Flatten the ENTIRE function dirtree: move every function out of every
    top-level folder back to the IDB root and delete the folders.

    Broader than xrefer's own roots on purpose — xrefer's folders use the
    generic names Library/User and can't be reliably distinguished from folders
    the user made by hand, so the honest reset removes them all. Returns the
    number of functions moved.
    """
    ft = _funcs_dirtree()
    moved = _flatten(ft, _top_level_dirs(ft))
    log(f"Removed all function folders ({moved} function(s) moved back to root)")
    return moved


def apply_function_folders(xrefer_obj) -> Tuple[int, int]:
    """Organize functions into ``/Library`` and ``/User`` folders from the
    per-function origin verdict.

    Idempotent: clears xrefer's existing folders first (so re-runs don't strand
    stale placements and every move starts from the root), then places each
    classified function. Functions not in the verdict — intermediates,
    unclustered, unknown — are left at the root untouched. Functions the user
    has filed into their *own* folders are also left alone (a move that doesn't
    originate from the root simply fails and is counted as skipped).

    Returns ``(moved, skipped)``.
    """
    ft = _funcs_dirtree()
    _flatten(ft, _XREFER_ROOTS)

    folders: Dict[int, List[str]] = xrefer_obj.compute_function_folders()
    moved = skipped = 0
    for ea, components in folders.items():
        fn = xrefer_obj._backend.get_function_at(Address(ea))
        name = getattr(fn, "name", None) if fn is not None else None
        if not name:
            skipped += 1
            continue
        rel = "/".join(components)
        try:
            _ensure_dir(ft, rel)
            if ft.rename(name, f"{rel}/{name}") == ida_dirtree.DTE_OK:
                moved += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1

    log(f"Organized {moved} function(s) into folders ({skipped} skipped)")
    return moved, skipped
