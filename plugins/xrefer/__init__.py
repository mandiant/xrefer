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

# NOTE: ASCII graph rendering now uses the pure-Python `ascii_graphs` package
# (a 1:1 port of the ascii-graphs Scala library) instead of `asciinet`/the JVM.
# The previous subprocess.Popen patch existed only to suppress the Java console
# window when asciinet spawned a JVM server; with no JVM it is no longer needed.

# ``__version__`` lives in a sibling module with zero imports so
# setuptools' AST-based ``attr:`` reader can resolve it at build time
# without importing the whole package. To bump the release version,
# edit ``plugins/xrefer/_version.py`` — that is the single source of
# truth. See pyproject.toml's ``[tool.setuptools.dynamic]`` section
# for the wiring.
from ._version import __version__

from . import core, lang, llm, loaders
from .api import analyze, available_backends

__all__ = ["core", "lang", "llm", "loaders", "analyze", "available_backends", "__version__"]
