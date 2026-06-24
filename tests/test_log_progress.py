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

"""log_progress: hot-loop progress without the logging tax.

Per-iteration log() calls (print + wait-box replace each) fired tens of
thousands of times per analysis. log_progress gates emissions to ~4Hz,
sends only every Nth emission to the full log channel, routes the rest to
the transient progress sink, and ALWAYS flushes final=True so the closing
[total/total] line lands.
"""

import pytest

import xrefer.core.helpers as helpers
from xrefer.core.helpers import log_progress, set_log_function, set_progress_function


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setitem(helpers._progress_state, "last", 0.0)
    monkeypatch.setitem(helpers._progress_state, "count", 0)
    yield
    set_log_function(None)
    set_progress_function(None)


def _wire(monkeypatch, times):
    clock = iter(times)
    monkeypatch.setattr(helpers, "monotonic", lambda: next(clock))
    logged, progressed = [], []
    set_log_function(logged.append)
    set_progress_function(progressed.append)
    return logged, progressed


def test_emissions_are_time_gated(monkeypatch):
    logged, progressed = _wire(monkeypatch, [1.0, 1.05, 1.10, 1.40])
    for i in range(4):
        log_progress(f"step {i}")
    # t=1.0 emits (first), 1.05/1.10 suppressed, 1.40 emits.
    assert len(logged) + len(progressed) == 2


def test_first_emission_goes_to_full_log_rest_to_sink(monkeypatch):
    logged, progressed = _wire(monkeypatch, [1.0, 2.0, 3.0, 4.0])
    for i in range(4):
        log_progress(f"step {i}")
    assert logged == ["step 0"]  # every-Nth policy: 1st of each 500 prints
    assert progressed == ["step 1", "step 2", "step 3"]


def test_final_always_lands_on_the_full_channel(monkeypatch):
    logged, progressed = _wire(monkeypatch, [1.0, 1.01, 1.02])
    log_progress("step 0")
    log_progress("step 1")          # suppressed by the gate
    log_progress("[10/10] done", final=True)  # gate bypassed, full channel
    assert logged == ["step 0", "[10/10] done"]
    assert progressed == []


def test_headless_default_prints(monkeypatch, capsys):
    clock = iter([1.0, 2.0])
    monkeypatch.setattr(helpers, "monotonic", lambda: next(clock))
    set_log_function(None)
    set_progress_function(None)
    log_progress("a")  # count=1 -> full log channel -> default print
    log_progress("b")  # sinkless -> fallback print
    out = capsys.readouterr().out
    assert "a" in out and "b" in out
