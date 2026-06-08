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

# Pin qtpy to PySide6 (the binding IDA 9.x actually runs on) before importing
# any submodule that imports qtpy. IDA's bundled PyQt5 is an incomplete compat
# shim that qtpy would otherwise select and choke on (missing pyqtBoundSignal).
# Mirrors the guard in the plugin entry point (plugins/xrefer.py); harmless if
# already set there. Only applies when PySide6 is importable and the user has
# not pinned QT_API themselves.
import importlib.util as _ilu
import os as _os

if "QT_API" not in _os.environ and _ilu.find_spec("PySide6") is not None:
    _os.environ["QT_API"] = "pyside6"
    _os.environ["FORCE_QT_API"] = "1"

from . import action_handlers, help, helpers, settings, state_machine, view

__all__ = ["action_handlers", "help", "helpers", "settings", "state_machine", "view"]
