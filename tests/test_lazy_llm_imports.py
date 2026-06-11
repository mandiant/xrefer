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

"""Plugin load must not import litellm/dspy.

The dspy/litellm chain costs a measured ~4s at import time, paid on every
IDA launch even in sessions that never touch LLM features. xrefer.llm
defers it: the package import (reached from core/analyzer at plugin scan
time) stays light, and the chain loads on first LLM use. Run in a
subprocess so the check sees a genuinely clean module table regardless of
what other tests imported.
"""

import pathlib
import subprocess
import sys

_REPO = pathlib.Path(__file__).resolve().parents[1]

_PROBE = """
import sys
import xrefer.core.analyzer  # the plugin-load import path
heavy = [m for m in ("litellm", "dspy") if m in sys.modules]
assert not heavy, f"plugin-load path imported heavy modules: {heavy}"
# Deferred chain still loads on demand and the lazy accessor resolves.
from xrefer.llm.cluster_analyzer import _llm_processor_cls
cls = _llm_processor_cls()
assert cls.__name__ == "LLMProcessor"
assert "litellm" in sys.modules and "dspy" in sys.modules
print("OK")
"""


def test_plugin_load_path_defers_heavy_llm_imports():
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(_REPO),
        env={"PYTHONPATH": str(_REPO / "plugins"), "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
