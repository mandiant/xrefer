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

"""_CallTimer: the wait-box freeze-expectation line.

The main thread blocks during every LLM call, so the pre-call message is
the analyst's only signal for minutes at a time. The timer's suffix must
state last/avg/ETA when samples exist, suppress the ETA when no remaining
count is given (heterogeneous hierarchical calls), and always carry the
unresponsiveness expectation.
"""

from xrefer.llm.cluster_analyzer import _CallTimer, _fmt_secs


def test_fmt_secs():
    assert _fmt_secs(5) == "5s"
    assert _fmt_secs(59.9) == "59s"
    assert _fmt_secs(60) == "1m00s"
    assert _fmt_secs(150) == "2m30s"


def test_no_samples_yields_expectation_only():
    t = _CallTimer()
    suffix = t.progress_suffix(5)
    assert suffix == " IDA is unresponsive during each call."


def test_average_and_eta_from_samples():
    t = _CallTimer()
    t.samples = [40.0, 60.0]  # avg 50
    suffix = t.progress_suffix(remaining_calls=3)
    assert "Last call 1m00s" in suffix
    assert "avg 50s" in suffix
    assert "~2m30s remaining" in suffix
    assert suffix.endswith("IDA is unresponsive during each call.")


def test_eta_suppressed_without_remaining_count():
    t = _CallTimer()
    t.samples = [12.0]
    suffix = t.progress_suffix()
    assert "remaining" not in suffix
    assert "Last call 12s" in suffix


def test_measure_records_wall_time(monkeypatch):
    t = _CallTimer()
    with t.measure():
        pass
    assert len(t.samples) == 1
    assert t.samples[0] >= 0.0


def test_measure_records_even_when_call_raises():
    t = _CallTimer()
    try:
        with t.measure():
            raise RuntimeError("call failed")
    except RuntimeError:
        pass
    assert len(t.samples) == 1  # retries/failures still count as wall time
