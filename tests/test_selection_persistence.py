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

"""Artifact selections persist with the analysis DB.

Selections gate B boundary scans and D exclusions yet used to live only in
an in-memory gui dict. The canonical store now sits on the CORE object
(plain ints, IDA-free), the state machine ADOPTS that same dict (mutating
it in place), save_analysis pickles it, the load path bounds-checks stale
indices, and rebase shifts the func_ea keys without touching the (image-
base independent) entity indices.
"""

import importlib.util
import pathlib
import sys
import types

from xrefer.core.analyzer import XRefer

_REPO = pathlib.Path(__file__).resolve().parents[1]


def _load_sm():
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []
            sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location(
        "xrefer.gui.state_machine", _REPO / "plugins" / "xrefer" / "gui" / "state_machine.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.state_machine"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_adopted_dict_is_mutated_in_place():
    core_store = {}
    sm = _load_sm().XReferStateMachine()
    sm.adopt_selected_refs(core_store)
    sm.update_selected_refs(0x1000, 7)
    sm.update_selected_refs(0x1000, 9)
    sm.update_selected_refs(0x1000, 7)  # toggle off
    assert core_store == {0x1000: {9}}  # the CORE dict carries the state


def test_restore_bounds_checks_stale_indices():
    # Mirrors the load-path comprehension: indices beyond the (re-analyzed,
    # shrunken) entity list are dropped; emptied functions disappear.
    master_struct = {"selected_refs": {0x1000: {0, 2, 99}, 0x2000: {50}}}
    n_entities = 3
    restored = {
        func_ea: kept
        for func_ea, idxs in (master_struct.get("selected_refs", {}) or {}).items()
        if (kept := {i for i in idxs if 0 <= i < n_entities})
    }
    assert restored == {0x1000: {0, 2}}


def test_rebase_shifts_keys_not_indices():
    xr = object.__new__(XRefer)
    shifted = xr.sync_image_base_dictkeys({0x1000: {3, 5}}, 0x10000)
    assert shifted == {0x11000: {3, 5}}
