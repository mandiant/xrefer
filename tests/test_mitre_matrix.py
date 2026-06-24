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

"""Tests for binary-wide MITRE ATT&CK aggregation (core/mitre).

Stub clusters carry only .id / .id_str / .subclusters / .is_library and a
hand-built cluster_analysis dict keyed by str(id) (one of the formats
find_cluster_analysis accepts). No IDA / backend / LLM needed.
"""

import csv
import io

from xrefer.core.mitre import (
    MITRE_TACTIC_ORDER,
    UNSPECIFIED_TACTIC,
    aggregate_mitre_matrix,
    has_any_techniques,
    mitre_attack_url,
    to_csv,
    to_navigator_layer,
    to_stix_bundle,
)


class _C:
    def __init__(self, cid, subclusters=None, is_library=False):
        self.id = cid
        self.id_str = f"{cid:04d}"
        self.subclusters = subclusters or []
        self.is_library = is_library


def _tech(tid, tactic, name="", rationale=""):
    return {"id": tid, "tactic": tactic, "name": name, "rationale": rationale}


def _analysis(mapping):
    """mapping: {cluster_id: [technique dicts]} -> cluster_analysis dict."""
    return {
        "clusters": {
            str(cid): {"label": f"C{cid}", "mitre_attack": techs}
            for cid, techs in mapping.items()
        }
    }


# --------------------------------------------------------------------------
# mitre_attack_url
# --------------------------------------------------------------------------

def test_url_parent_technique():
    assert mitre_attack_url("T1027") == "https://attack.mitre.org/techniques/T1027/"


def test_url_subtechnique():
    assert mitre_attack_url("T1059.003") == "https://attack.mitre.org/techniques/T1059/003/"


def test_url_normalizes_case_and_space():
    assert mitre_attack_url("  t1059.003 ") == "https://attack.mitre.org/techniques/T1059/003/"


def test_url_rejects_non_canonical():
    assert mitre_attack_url("nonsense") is None
    assert mitre_attack_url("T123") is None
    assert mitre_attack_url("") is None


# --------------------------------------------------------------------------
# aggregation basics
# --------------------------------------------------------------------------

def test_empty_when_no_analysis():
    m = aggregate_mitre_matrix([_C(1)], None)
    assert m.is_empty
    assert m.technique_count == 0
    assert m.total_clusters == 1
    assert m.clusters_with_techniques == 0


def test_single_cluster_single_technique():
    clusters = [_C(1)]
    ca = _analysis({1: [_tech("T1059.003", "Execution", "Windows Command Shell", "spawns cmd.exe")]})
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 1
    assert m.tactic_count == 1
    assert m.clusters_with_techniques == 1
    assert m.tactics[0].tactic == "Execution"
    t = m.tactics[0].techniques[0]
    assert t.id == "T1059.003"
    assert t.name == "Windows Command Shell"
    assert t.cluster_ids == [1]
    assert t.representative_rationale == "spawns cmd.exe"


def test_same_technique_across_clusters_merges():
    clusters = [_C(1), _C(2)]
    ca = _analysis({
        1: [_tech("T1027", "Defense Evasion", "Obfuscated Files", "xor blob")],
        2: [_tech("T1027", "Defense Evasion", "Obfuscated Files or Information", "")],
    })
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 1  # merged, not duplicated
    t = m.tactics[0].techniques[0]
    assert t.cluster_count == 2
    assert t.cluster_ids == [1, 2]
    # Longest name wins; first non-empty rationale is representative.
    assert t.name == "Obfuscated Files or Information"
    assert t.representative_rationale == "xor blob"


def test_case_insensitive_id_merge():
    clusters = [_C(1), _C(2)]
    ca = _analysis({
        1: [_tech("T1071.001", "Command and Control", "Web Protocols")],
        2: [_tech("t1071.001", "Command and Control", "Web Protocols")],
    })
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 1
    assert m.tactics[0].techniques[0].cluster_count == 2


# --------------------------------------------------------------------------
# ordering
# --------------------------------------------------------------------------

def test_tactics_sorted_by_kill_chain():
    clusters = [_C(1)]
    ca = _analysis({1: [
        _tech("T1486", "Impact"),
        _tech("T1059", "Execution"),
        _tech("T1190", "Initial Access"),
    ]})
    m = aggregate_mitre_matrix(clusters, ca)
    assert [g.tactic for g in m.tactics] == ["Initial Access", "Execution", "Impact"]


def test_techniques_within_tactic_sorted_by_coverage_then_id():
    clusters = [_C(1), _C(2), _C(3)]
    ca = _analysis({
        1: [_tech("T1059", "Execution"), _tech("T1106", "Execution")],
        2: [_tech("T1106", "Execution")],            # T1106 -> 2 clusters
        3: [_tech("T1106", "Execution")],            # T1106 -> 3 clusters
    })
    m = aggregate_mitre_matrix(clusters, ca)
    exec_group = m.tactics[0]
    # T1106 (3 clusters) before T1059 (1 cluster)
    assert [t.id for t in exec_group.techniques] == ["T1106", "T1059"]


def test_unspecified_tactic_bucketed_last():
    clusters = [_C(1)]
    ca = _analysis({1: [
        _tech("T1059", "Execution"),
        _tech("T1234", ""),  # no tactic
    ]})
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.tactics[-1].tactic == UNSPECIFIED_TACTIC
    assert m.tactics[-1].techniques[0].id == "T1234"


# --------------------------------------------------------------------------
# coverage strip
# --------------------------------------------------------------------------

def test_coverage_lists_all_canonical_tactics():
    clusters = [_C(1)]
    ca = _analysis({1: [_tech("T1059", "Execution"), _tech("T1059.003", "Execution")]})
    m = aggregate_mitre_matrix(clusters, ca)
    cov = dict(m.coverage)
    # every canonical tactic present, in order, with the right counts
    assert [t for t, _ in m.coverage][:len(MITRE_TACTIC_ORDER)] == MITRE_TACTIC_ORDER
    assert cov["Execution"] == 2
    assert cov["Impact"] == 0
    assert m.max_tactic_count == 2
    assert "Reconnaissance" in m.uncovered_tactics
    assert "Execution" not in m.uncovered_tactics


# --------------------------------------------------------------------------
# name / tactic resolution
# --------------------------------------------------------------------------

def test_tactic_vote_breaks_disagreement():
    clusters = [_C(1), _C(2), _C(3)]
    ca = _analysis({
        1: [_tech("T1055", "Defense Evasion")],
        2: [_tech("T1055", "Defense Evasion")],
        3: [_tech("T1055", "Privilege Escalation")],
    })
    m = aggregate_mitre_matrix(clusters, ca)
    # Defense Evasion has the majority (2 vs 1).
    assert m.tactics[0].techniques[0].tactic == "Defense Evasion"


# --------------------------------------------------------------------------
# scope + hide_library + subclusters
# --------------------------------------------------------------------------

def test_subclusters_are_walked():
    clusters = [_C(1, subclusters=[_C(5)])]
    ca = _analysis({
        1: [_tech("T1059", "Execution")],
        5: [_tech("T1027", "Defense Evasion")],
    })
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 2
    assert m.total_clusters == 2


def test_scope_limits_to_one_cluster_and_its_subs():
    clusters = [_C(1, subclusters=[_C(5)]), _C(2)]
    ca = _analysis({
        1: [_tech("T1059", "Execution")],
        5: [_tech("T1027", "Defense Evasion")],
        2: [_tech("T1486", "Impact")],
    })
    m = aggregate_mitre_matrix(clusters, ca, scope_cluster_id=1)
    ids = {t.id for g in m.tactics for t in g.techniques}
    assert ids == {"T1059", "T1027"}  # cluster 2's Impact excluded
    assert m.scope_cluster_id == 1
    assert m.total_clusters == 2  # cluster 1 + subcluster 5


def test_hide_library_prunes_library_clusters():
    clusters = [_C(1), _C(2, is_library=True)]
    ca = _analysis({
        1: [_tech("T1059", "Execution")],
        2: [_tech("T1486", "Impact")],
    })
    full = aggregate_mitre_matrix(clusters, ca, hide_library=False)
    pruned = aggregate_mitre_matrix(clusters, ca, hide_library=True)
    assert full.technique_count == 2
    assert pruned.technique_count == 1
    assert pruned.total_clusters == 1


# --------------------------------------------------------------------------
# pydantic-style entries (model_dump) + key-format tolerance
# --------------------------------------------------------------------------

class _PydLike:
    def __init__(self, **kw):
        self._d = kw

    def model_dump(self):
        return dict(self._d)


def test_accepts_model_dump_entries():
    clusters = [_C(1)]
    ca = {
        "clusters": {
            "cluster_1": {  # cluster_ prefix variant
                "label": "C1",
                "mitre_attack": [_PydLike(id="T1059", tactic="Execution", name="n", rationale="r")],
            }
        }
    }
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 1
    assert m.tactics[0].techniques[0].representative_rationale == "r"


def test_entry_without_id_is_dropped():
    clusters = [_C(1)]
    ca = _analysis({1: [_tech("", "Execution", "no id"), _tech("T1059", "Execution")]})
    m = aggregate_mitre_matrix(clusters, ca)
    assert m.technique_count == 1
    assert m.tactics[0].techniques[0].id == "T1059"


# --------------------------------------------------------------------------
# has_any_techniques (menu/popup gate)
# --------------------------------------------------------------------------

def test_has_any_techniques():
    assert has_any_techniques(None) is False
    assert has_any_techniques({}) is False
    assert has_any_techniques(_analysis({1: []})) is False
    assert has_any_techniques(_analysis({1: [_tech("", "Execution")]})) is False  # no id
    assert has_any_techniques(_analysis({1: [_tech("T1059", "Execution")]})) is True


# --------------------------------------------------------------------------
# ATT&CK Navigator layer export
# --------------------------------------------------------------------------

def _sample_matrix():
    clusters = [_C(1), _C(2)]
    ca = _analysis({
        1: [_tech("T1059.003", "Execution", "Windows Command Shell", "spawns cmd.exe"),
            _tech("T1071.001", "Command and Control", "Web Protocols", "https beacon")],
        2: [_tech("T1059.003", "Execution", "Windows Command Shell", "also cmd")],
    })
    return aggregate_mitre_matrix(clusters, ca)


def test_navigator_layer_structure():
    layer = to_navigator_layer(_sample_matrix(), name="sample", description="d")
    assert layer["name"] == "sample"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1059.003", "T1071.001"}
    # score = #clusters; T1059.003 is in 2 clusters
    assert by_id["T1059.003"]["score"] == 2
    # tactic shortname pins the cell to the right column
    assert by_id["T1059.003"]["tactic"] == "execution"
    assert by_id["T1071.001"]["tactic"] == "command-and-control"
    assert by_id["T1059.003"]["comment"] == "spawns cmd.exe"
    md = {m["name"]: m["value"] for m in by_id["T1059.003"]["metadata"]}
    assert md["clusters"] == "0001, 0002"
    assert layer["gradient"]["maxValue"] == 2


# --------------------------------------------------------------------------
# STIX 2.1 bundle export
# --------------------------------------------------------------------------

def test_stix_bundle_structure_and_determinism():
    m = _sample_matrix()
    b1 = to_stix_bundle(m, created="2020-01-01T00:00:00.000Z", name="sample")
    b2 = to_stix_bundle(m, created="2020-01-01T00:00:00.000Z", name="sample")
    assert b1 == b2  # deterministic ids (uuid5) + fixed timestamp
    assert b1["type"] == "bundle"
    assert b1["id"].startswith("bundle--")
    aps = [o for o in b1["objects"] if o["type"] == "attack-pattern"]
    assert len(aps) == 2
    cmd = next(o for o in aps if o["name"] == "Windows Command Shell")
    assert cmd["spec_version"] == "2.1"
    assert cmd["id"].startswith("attack-pattern--")
    ref = cmd["external_references"][0]
    assert ref["source_name"] == "mitre-attack"
    assert ref["external_id"] == "T1059.003"
    assert ref["url"].endswith("/T1059/003/")
    assert cmd["kill_chain_phases"][0]["phase_name"] == "execution"
    assert cmd["x_xrefer_cluster_count"] == 2
    assert cmd["x_xrefer_clusters"] == ["0001", "0002"]


# --------------------------------------------------------------------------
# CSV export
# --------------------------------------------------------------------------

def test_csv_export():
    rows = list(csv.reader(io.StringIO(to_csv(_sample_matrix()))))
    assert rows[0] == ["tactic", "technique_id", "name", "cluster_count", "clusters", "rationale"]
    body = rows[1:]
    assert len(body) == 2  # one row per unique technique
    by_id = {r[1]: r for r in body}
    assert by_id["T1059.003"][0] == "Execution"
    assert by_id["T1059.003"][3] == "2"
    assert by_id["T1059.003"][4] == "0001 0002"
