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

"""Every state-machine member the view references must actually exist.

view.py held ~65 ``self.state_machine.<name>`` references and exactly one
named a transition that was never defined (``end_last_boundary_results``)
— a guaranteed AttributeError on a documented key's first press. This
scrape closes the whole bug class: the real source is parsed for every
referenced member and each is asserted against a real XReferStateMachine
instance (loaded directly from gui/state_machine.py, which imports no IDA
modules — the xrefer.gui package __init__ does and cannot be imported
headlessly).
"""

import importlib.util
import pathlib
import re
import sys
import types

_REPO = pathlib.Path(__file__).resolve().parents[1]
_GUI = _REPO / "plugins" / "xrefer" / "gui"


def _load_state_machine_module():
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []
            sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location("xrefer.gui.state_machine", _GUI / "state_machine.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.state_machine"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_every_state_machine_reference_in_view_exists():
    source = (_GUI / "view.py").read_text(encoding="utf-8")
    referenced = sorted(set(re.findall(r"self\.state_machine\.([A-Za-z_]\w*)", source)))
    assert len(referenced) > 30, "scrape went wrong — far fewer refs than expected"

    sm = _load_state_machine_module().XReferStateMachine()
    missing = [name for name in referenced if not hasattr(sm, name)]
    assert not missing, (
        f"view.py references state-machine members that do not exist: {missing} "
        "(an AttributeError waiting for the first keypress that reaches them)"
    )


def test_help_and_action_handler_references_exist_too():
    sm_mod = _load_state_machine_module()
    sm = sm_mod.XReferStateMachine()
    for fname in ("help.py", "action_handlers.py", "state_machine.py"):
        source = (_GUI / fname).read_text(encoding="utf-8")
        referenced = set(re.findall(r"state_machine\.([A-Za-z_]\w*)", source))
        # "state_machine.py" in prose/docstrings matches as attribute "py".
        referenced.discard("py")
        missing = [n for n in sorted(referenced) if not hasattr(sm, n) and not hasattr(sm_mod, n)]
        assert not missing, f"{fname} references missing state-machine members: {missing}"
