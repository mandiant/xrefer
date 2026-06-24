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

"""Hash-indexed entity interning must behave exactly like the linear scan.

set_and_get_entity_index used to scan all entities per call (quadratic on
string-heavy binaries). The replacement keeps a lazily-synced map; the two
ways it could silently regress dedup are locked here: entries APPENDED
directly to entities (load_imports) must stay dedupable by later intern
calls, and unhashable post-enrichment 7-tuples must be skipped without
breaking lookups. Also covers the one-pass entity_xrefs back-fill in
_group_interesting_artifacts.
"""

from xrefer.core.analyzer import EntityType, Reference, XRefer


def _bare_xrefer():
    xr = object.__new__(XRefer)
    xr.entities = []
    return xr


def test_intern_dedupes_and_appends():
    xr = _bare_xrefer()
    a = xr.set_and_get_entity_index(("kernel32", "CreateFileW", EntityType.IMPORT))
    b = xr.set_and_get_entity_index(("kernel32", "ReadFile", EntityType.IMPORT))
    a_again = xr.set_and_get_entity_index(("kernel32", "CreateFileW", EntityType.IMPORT))
    assert (a, b, a_again) == (0, 1, 0)
    assert len(xr.entities) == 2


def test_intern_handles_bare_strings_alongside_tuples():
    # sift_strings interns plain strings into the same list.
    xr = _bare_xrefer()
    s = xr.set_and_get_entity_index("http://evil.example/c2")
    t = xr.set_and_get_entity_index(("libc", "memcpy", EntityType.LIBRARY))
    assert s == 0 and t == 1
    assert xr.set_and_get_entity_index("http://evil.example/c2") == 0


def test_direct_appends_remain_dedupable():
    # load_imports appends straight to entities; a later intern of the
    # identical tuple (process_api_trace) must find it, not duplicate it.
    xr = _bare_xrefer()
    xr.set_and_get_entity_index(("seed", "seed", EntityType.IMPORT))
    xr.entities.append(("kernel32", "VirtualAlloc", EntityType.IMPORT))
    idx = xr.set_and_get_entity_index(("kernel32", "VirtualAlloc", EntityType.IMPORT))
    assert idx == 1
    assert len(xr.entities) == 2


def test_wholesale_replacement_with_unhashable_entries():
    # Enrichment replaces entities with a new list whose 7-tuples carry a
    # dict and a list (unhashable). Lookups must keep working and the
    # unhashable rows must be skipped, exactly as the equality scan would
    # never have matched them against hashable probes.
    xr = _bare_xrefer()
    xr.set_and_get_entity_index(("old", "old", EntityType.IMPORT))
    enriched = [
        ("cat", "string-a", EntityType.STRING, 1, {"repo": ["line"]}, ["repo"], 0.5),
        ("kernel32", "CreateFileW", EntityType.IMPORT),
    ]
    xr.entities = enriched
    assert xr.set_and_get_entity_index(("kernel32", "CreateFileW", EntityType.IMPORT)) == 1
    new = xr.set_and_get_entity_index(("ws2_32", "send", EntityType.IMPORT))
    assert new == 2 and len(xr.entities) == 3


def test_first_match_wins_like_the_linear_scan():
    xr = _bare_xrefer()
    dup = ("libc", "strlen", EntityType.LIBRARY)
    xr.entities = [dup, ("x", "y", EntityType.IMPORT), dup]
    assert xr.set_and_get_entity_index(dup) == 0


def test_group_artifacts_backfills_xrefs_in_one_pass():
    xr = _bare_xrefer()
    xr.settings = {"enable_exclusions": False}
    xr.excluded_entities = set()
    xr.entities = ["str-a", "str-b", "str-c"]
    xr.entity_xrefs = {0: {0x111}}  # idx 0 already known
    xr.mapped_refs = [
        Reference(0x222, 1, EntityType.STRING),
        Reference(0x223, 1, EntityType.STRING),
        # idx 2 has no refs at all -> must NOT get an (empty) entry written
    ]
    calls = []
    xr._process_artifact_xrefs = lambda *a, **k: calls.append(a)

    xr._group_interesting_artifacts({0, 1, 2})

    assert xr.entity_xrefs[1] == {0x222, 0x223}
    assert 2 not in xr.entity_xrefs  # no empty set persisted
    assert len(calls) == 2  # idx 0 and idx 1 processed; idx 2 went orphan
