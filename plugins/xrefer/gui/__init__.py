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

# Pin qtpy to PySide6 (IDA 9.x's real binding) before importing any submodule
# that imports qtpy. Robust mirror of plugins/xrefer.py::_pin_qt_binding — see
# there for the full rationale. Key points: qtpy *writes* QT_API to whatever it
# selected (so a "respect QT_API" check is fooled once a shim-bound qtpy ran),
# and an already-wrongly-bound qtpy must be purged so it re-selects. Only acts
# when PySide6 is present (Qt6 IDA); a Qt5 IDA keeps real PyQt5.
import importlib.util as _ilu
import os as _os
import sys as _sys

try:
    _have_pyside6 = "PySide6" in _sys.modules or _ilu.find_spec("PySide6") is not None
except Exception:
    _have_pyside6 = "PySide6" in _sys.modules
_q = _sys.modules.get("qtpy")
if _have_pyside6 and not (_q is not None and getattr(_q, "API_NAME", "").lower() == "pyside6"):
    _os.environ["QT_API"] = "pyside6"
    _os.environ["FORCE_QT_API"] = "1"
    if _q is not None:
        for _m in [_k for _k in _sys.modules if _k == "qtpy" or _k.startswith("qtpy.")]:
            del _sys.modules[_m]

from . import action_handlers, help, helpers, settings, state_machine, view

__all__ = ["action_handlers", "help", "helpers", "settings", "state_machine", "view"]
