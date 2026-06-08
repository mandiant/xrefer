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

import importlib.util
import os
import sys


def _pin_qt_binding():
    """Make qtpy use the Qt binding IDA actually runs on — robustly.

    IDA 9.x runs its GUI on PySide6 (Qt6) but also ships an *incomplete* PyQt5
    compatibility shim (toggled by IDAPYTHON_USE_PYQT5_SHIM in idapython.cfg).
    qtpy defaults to PyQt5, so with the shim enabled it binds to that shim and
    then dies on the missing ``pyqtBoundSignal`` — the plugin fails to load.
    On older Qt5 IDA there is no PySide6 and PyQt5 is the real binding, so we
    leave qtpy alone there.

    We can't simply key off QT_API: qtpy *writes* QT_API to whatever binding it
    selected, so once any plugin imports qtpy under the shim, QT_API=pyqt5 is
    left behind and a "respect the user's QT_API" check would wrongly bail. So
    we key off whether PySide6 is importable, and — crucially — if qtpy was
    already imported and bound to something other than PySide6, we drop it from
    sys.modules so the next import re-selects. FORCE_QT_API stops qtpy from
    re-preferring a PyQt5 shim that is still in sys.modules. A shim-bound qtpy
    is unusable anyway, so purging it harms nothing and fixes it for everyone.
    Runs before anything imports qtpy.
    """
    try:
        have_pyside6 = "PySide6" in sys.modules or importlib.util.find_spec("PySide6") is not None
    except Exception:
        have_pyside6 = "PySide6" in sys.modules
    if not have_pyside6:
        return  # Qt5 IDA: real PyQt5 is the right binding; do not interfere
    qtpy = sys.modules.get("qtpy")
    if qtpy is not None and getattr(qtpy, "API_NAME", "").lower() == "pyside6":
        return  # already on PySide6
    os.environ["QT_API"] = "pyside6"
    os.environ["FORCE_QT_API"] = "1"
    if qtpy is not None:
        for _name in [m for m in sys.modules if m == "qtpy" or m.startswith("qtpy.")]:
            del sys.modules[_name]


_pin_qt_binding()

plugin_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(plugin_dir, "xrefer"))

from xrefer.plugin import XReferPlugin


def PLUGIN_ENTRY():
    """
    Entry point for the IDA plugin.

    Returns:
        XReferPlugin: A new instance of the XRefer plugin.
    """
    return XReferPlugin()
