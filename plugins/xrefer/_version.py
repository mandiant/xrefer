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

# Single source of truth for xrefer's release version.
#
# Format: ``MAJOR.MINOR.YYYYMMDD`` — PEP 440-compliant, three numeric
# segments separated by dots. Bump this constant when cutting a release;
# everything downstream (the package's ``__version__`` attribute,
# ``pyproject.toml``'s build-time version, the IDA startup log, the
# About dialog, the HTML report metadata) reads from here.
#
# This file deliberately has NO imports so setuptools' AST-based
# ``attr:`` reader can resolve the version statically — without
# importing the ``xrefer`` package — at build/lock time. Keep it that
# way; adding any import would force a dynamic-import fallback that
# breaks ``uv lock`` because of the ``plugins/xrefer.py`` IDA-loader
# vs. ``plugins/xrefer/`` package name collision.

__version__ = "1.1.20260804"
