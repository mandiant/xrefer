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

"""Tests for cap_artifact_entries — the per-type cap behind the optional
"cap artifacts per type in graph nodes" setting (graph node-detail / D mode).

Pure logic, no IDA: the overflow colour is supplied by the caller, so the
helper that the GUI's _node_artifact_entries delegates to is fully testable
here.
"""

from xrefer.core.helpers import cap_artifact_entries

IMP, STR, OFLOW = 1, 2, 9  # arbitrary distinct "colour" ints


def _pt(imports=0, strings=0):
    return [
        ("imports", [(f"imp{i}", IMP) for i in range(imports)]),
        ("strings", [(f"str{i}", STR) for i in range(strings)]),
    ]


def test_no_cap_passes_everything_through():
    pt = _pt(imports=10, strings=3)
    out = cap_artifact_entries(pt, None, OFLOW)
    assert out == [(f"imp{i}", IMP) for i in range(10)] + [(f"str{i}", STR) for i in range(3)]


def test_zero_or_negative_cap_means_no_cap():
    pt = _pt(imports=5)
    assert cap_artifact_entries(pt, 0, OFLOW) == [(f"imp{i}", IMP) for i in range(5)]
    assert cap_artifact_entries(pt, -3, OFLOW) == [(f"imp{i}", IMP) for i in range(5)]


def test_caps_each_type_independently_with_overflow_line():
    pt = _pt(imports=10, strings=2)
    out = cap_artifact_entries(pt, 6, OFLOW)
    # imports capped to 6 + a "(+4 more)" overflow; strings under cap -> untouched
    assert out == (
        [(f"imp{i}", IMP) for i in range(6)]
        + [("(+4 more)", OFLOW)]
        + [(f"str{i}", STR) for i in range(2)]
    )


def test_exactly_at_cap_has_no_overflow():
    out = cap_artifact_entries(_pt(imports=6), 6, OFLOW)
    assert out == [(f"imp{i}", IMP) for i in range(6)]
    assert all(not t.startswith("(+") for t, _ in out)


def test_both_types_overflow_get_their_own_line():
    out = cap_artifact_entries(_pt(imports=9, strings=9), 6, OFLOW)
    assert out.count(("(+3 more)", OFLOW)) == 2
    assert len(out) == 6 + 1 + 6 + 1


def test_overflow_format_is_customizable():
    out = cap_artifact_entries(_pt(imports=8), 5, OFLOW, overflow_fmt="+{count}")
    assert out[-1] == ("+3", OFLOW)


def test_empty_inputs():
    assert cap_artifact_entries([], 6, OFLOW) == []
    assert cap_artifact_entries([("imports", [])], 6, OFLOW) == []


def test_overflow_uses_the_supplied_colour():
    out = cap_artifact_entries(_pt(imports=20), 6, 0xABC)
    assert out[6] == ("(+14 more)", 0xABC)
