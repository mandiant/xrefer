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

"""User cancellation of long-running analysis phases.

The cancellation probe is injected by the GUI (IDA's user_cancelled) via
core/helpers.set_cancel_check — same pattern as set_log_function — so the
core/llm layers stay IDA-free and headless runs default to never-cancelled.
These tests lock:

  * the probe/phase helpers (defaults, injection, nesting);
  * path building honoring Cancel both between leaves and inside the BFS,
    raising AnalysisCancelled;
  * the abandon path leaving a consistent not-analyzed state (in-progress
    EP removed from paths so "already analyzed?" checks stay honest) and
    never persisting partial results.
"""

import pytest

import xrefer.core.helpers as core_helpers
from xrefer.core.analyzer import XRefer
from xrefer.core.helpers import AnalysisCancelled, cancellable_phase, check_cancelled, in_cancellable_phase, set_cancel_check


@pytest.fixture(autouse=True)
def _reset_probe():
    yield
    set_cancel_check(None)


def test_defaults_never_cancelled():
    assert check_cancelled() is False
    assert in_cancellable_phase() is False


def test_probe_injection_and_error_tolerance():
    set_cancel_check(lambda: True)
    assert check_cancelled() is True

    def _broken():
        raise RuntimeError("probe died")

    set_cancel_check(_broken)
    assert check_cancelled() is False  # a broken probe must not abort work


def test_cancellable_phase_nests():
    assert not in_cancellable_phase()
    with cancellable_phase():
        assert in_cancellable_phase()
        with cancellable_phase():
            assert in_cancellable_phase()
        assert in_cancellable_phase()
    assert not in_cancellable_phase()


class _FakeFn:
    def __init__(self, name):
        self.name = name


class _FakeBackend:
    def get_function_at(self, address):
        return _FakeFn(f"sub_{int(address):x}")


def _bare_xrefer():
    xr = object.__new__(XRefer)
    xr._backend = _FakeBackend()
    xr.current_analysis_ep = 0x1000
    xr.paths = {}
    xr.leaf_funcs = {0x9000}
    xr.caller_xrefs_cache = {0x1000: {0x9000: {0x1010}}}
    return xr


def test_leaf_loop_raises_on_cancel():
    set_cancel_check(lambda: True)
    xr = _bare_xrefer()
    with pytest.raises(AnalysisCancelled):
        xr.generate_all_simple_call_paths_for_ep()


def test_bfs_inner_loop_raises_on_cancel():
    # A long predecessor chain forces >1024 BFS iterations; the in-loop
    # check must fire even though no leaf boundary is crossed.
    set_cancel_check(lambda: True)
    xr = _bare_xrefer()
    chain = {i: {i + 1} for i in range(3000)}  # preds: node i has caller i+1
    with pytest.raises(AnalysisCancelled):
        xr.generate_simple_call_paths(3000, 0, chain)


def test_abandon_leaves_consistent_state(monkeypatch):
    xr = _bare_xrefer()
    xr.paths = {0x1000: {}}  # in-progress (empty) entry for the cancelled EP
    saves = []
    monkeypatch.setattr(XRefer, "save_analysis", lambda self: saves.append(1), raising=True)
    xr._abandon_cancelled_run()
    assert 0x1000 not in xr.paths  # "already analyzed?" answers no again
    assert not saves  # nothing persisted


def test_uncancelled_run_unaffected():
    set_cancel_check(lambda: False)
    xr = _bare_xrefer()
    xr.generate_all_simple_call_paths_for_ep()
    assert list(xr.paths[0x1000][0x9000]) == [[0x1000, 0x9000]]
