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

# IDA 9.x runs its GUI on PySide6 (Qt6) but also ships an *incomplete* PyQt5
# compatibility shim (enabled via IDAPYTHON_USE_PYQT5_SHIM=1 in idapython.cfg).
# qtpy defaults to PyQt5 and, when that shim is enabled, binds to it and then
# dies on the missing `pyqtBoundSignal`. Pin qtpy to the real binding IDA uses
# — PySide6 — whenever it is importable, unless the user explicitly chose one
# via QT_API. FORCE_QT_API stops qtpy from re-selecting an already-imported
# PyQt5 shim. This must run before anything imports qtpy.
if "QT_API" not in os.environ and importlib.util.find_spec("PySide6") is not None:
    os.environ["QT_API"] = "pyside6"
    os.environ["FORCE_QT_API"] = "1"

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
