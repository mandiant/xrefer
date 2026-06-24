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

"""Categorization failures must degrade, never abort the analysis.

Two layers are locked in:

  * ``Categorizer.categorize`` — a failed LLM call surfaces as a result
    without ``category_assignments`` (the processor absorbs rate limits and
    returns {}); categorize must return its inputs unchanged instead of
    KeyError-ing.
  * the ``sift_libs`` / ``load_imports`` call sites — error classes the
    processor does NOT absorb (auth, connectivity, timeout) used to
    propagate raw out of ``analyze()`` before ``save_analysis``/
    ``save_categories`` ran, losing the entire run. They now degrade to the
    default grouping the per-item fallbacks already implement.
"""

import pytest

from xrefer.core.analyzer import EntityType, XRefer
from xrefer.llm.categorizer import CATEGORIES, Categorizer


class _FakeProcessor:
    def __init__(self, result=None, exc=None):
        self.result = result if result is not None else {}
        self.exc = exc

    def validate_api_key(self):
        return True

    def process_items(self, **kwargs):
        if self.exc is not None:
            raise self.exc
        return self.result


@pytest.fixture(autouse=True)
def _reset_categorizer():
    saved_processor = Categorizer._processor
    saved_config = Categorizer.current_config
    yield
    Categorizer._processor = saved_processor
    Categorizer.current_config = saved_config


def test_categorize_returns_inputs_unchanged_on_empty_result():
    Categorizer._processor = _FakeProcessor(result={})
    existing = {"CreateFileW": 0}
    items, cats = Categorizer.categorize(["CreateFileW", "RegOpenKeyExW"], existing)
    assert items == {"CreateFileW": 0}
    assert cats == CATEGORIES


def test_categorize_applies_assignments_on_success():
    Categorizer._processor = _FakeProcessor(result={"category_assignments": {"0": 3}})
    items, _ = Categorizer.categorize(["RegOpenKeyExW"], {})
    assert items == {"RegOpenKeyExW": 3}


def _bare_xrefer():
    o = object.__new__(XRefer)
    o.llm_lookups = True
    o.mode = "full"
    o.entities = []
    o.categories = {"libs": {}, "lib_categories": [], "apis": {}, "api_categories": []}
    o.lib_refs = []
    o.imports = []
    return o


class _Lang:
    # (xref_addr, name, call_site, default_category)
    lib_refs = [(0x1000, "memcpy", 0x1004, "libc")]


class _Backend:
    def get_imports(self):
        return [(0x2000, "CreateFileW", "kernel32")]


@pytest.mark.parametrize("exc", [RuntimeError("auth failure"), ConnectionError("api down")])
def test_sift_libs_degrades_when_categorize_raises(monkeypatch, exc):
    def _boom(*a, **k):
        raise exc

    monkeypatch.setattr(Categorizer, "categorize", _boom)
    xr = _bare_xrefer()
    xr.lang = _Lang()
    xr.sift_libs()
    # The run continued and the lib ref landed with its default category.
    assert len(xr.lib_refs) == 1
    assert xr.entities == [("libc", "memcpy", EntityType.LIBRARY)]


def test_load_imports_degrades_when_categorize_raises(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("auth failure")

    monkeypatch.setattr(Categorizer, "categorize", _boom)
    xr = _bare_xrefer()
    xr._backend = _Backend()
    xr.load_imports()
    assert len(xr.imports) == 1
    assert xr.entities == [("kernel32", "CreateFileW", EntityType.IMPORT)]
