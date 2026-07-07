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

"""Tests for the agent-facing exports (core/agent_map): the single-file
``binary_anatomy`` and the tiered ``xrefer-agent-map`` bundle.

Everything runs on lightweight stubs (fake clusters + a hand-built
global_xrefs / entities / paths / cluster_analysis + a dark backend). No IDA,
backend, or LLM is needed, so the provenance discipline, RVA encoding,
cross-file resolvability, manifest integrity, and degrade-without-LLM
behaviour are all exercised deterministically.
"""

import json

from xrefer.core.agent_map import (
    GUESS,
    build_agent_map,
    build_anatomy,
    export_agent_map,
)

# Entity type ids (mirror EntityType: 1=lib 2=import 3=string 4=capa 5=api_trace).
IMPORT, STRING, CAPA = 2, 3, 4

IB = 0x400000
EP = 0x401000


class _Cluster:
    def __init__(self, cid, root, nodes, edges=None, is_library=False,
                 parent=None, cluster_refs=None, subclusters=None):
        self.id = cid
        self.id_str = f"{cid:04d}"
        self.root_node = root
        self.nodes = set(nodes)
        self.edges = edges or []
        self.is_library = is_library
        self.parent_cluster_id = parent
        self.cluster_refs = cluster_refs or {}
        self.subclusters = subclusters or []
        self.intermediate_paths = {}


class _Backend:
    """A deliberately dark backend (get_function_at -> None) so the export
    exercises its headless fallbacks, exactly like a load-from-cache CLI run."""

    def __init__(self, path):
        self.path = path
        self.image_base = IB

    @property
    def binary_hash(self):
        return "a" * 64

    def filetype(self):
        return "PE"

    def get_function_at(self, address):
        return None

    def read_bytes(self, address, size):
        return None


def _dxref(imports=None, strings=None, capa=None, imports_ea=None,
           strings_ea=None, capa_ea=None):
    z = {"libs": set(), "imports": set(), "strings": set(), "capa": set(),
         "api_trace": set(), "libs_ea": {}, "imports_ea": {}, "strings_ea": {},
         "capa_ea": {}, "api_trace_ea": {}}
    if imports:
        z["imports"] = set(imports)
    if strings:
        z["strings"] = set(strings)
    if capa:
        z["capa"] = set(capa)
    z["imports_ea"] = imports_ea or {}
    z["strings_ea"] = strings_ea or {}
    z["capa_ea"] = capa_ea or {}
    return z


class _XRefer:
    """Minimal analysed-instance stub with two clusters: a signal cluster that
    reaches a process-injection danger floor (reachable from entry) and an
    LLM-flagged library cluster (demoted, no danger floor)."""

    DIRECT_XREFS = 0
    INDIRECT_XREFS = 1

    def __init__(self, with_llm=True):
        self.image_base = IB
        self.current_analysis_ep = EP
        self._backend = _Backend("/tmp/sample.bin")
        self.lang = None

        # entities: 2 injection imports, 1 string, 1 capa
        # (group, name, type_id)
        self.entities = [
            ("kernel32", "VirtualAllocEx", IMPORT),      # 0
            ("kernel32", "WriteProcessMemory", IMPORT),  # 1
            ("rdata", "http://c2.example/beacon", STRING),  # 2
            ("host-interaction/process/inject", "inject process", CAPA),  # 3
        ]

        # Signal cluster A: root 0x402000, member 0x402100 bears the artifacts.
        # Library cluster B: root 0x403000 (is_library -> llm_lib, no danger).
        self.clusters = [
            _Cluster(1, 0x402000, [0x402000, 0x402100],
                     edges=[(0x402000, 0x402100)],
                     cluster_refs={0x402100: 2}),
            _Cluster(2, 0x403000, [0x403000], is_library=True),
        ]

        # global_xrefs: 0x402100 references both imports (with call sites),
        # the string, and the capa; the root gates them indirectly.
        self.global_xrefs = {
            0x402000: [_dxref(), _dxref(imports={0, 1}, capa={3})],  # indirect hub
            0x402100: [
                _dxref(imports={0, 1}, strings={2}, capa={3},
                       imports_ea={0: {0x402130}, 1: {0x402150}},
                       strings_ea={2: {0x402120}},
                       capa_ea={3: {0x402150}}),
                _dxref(),
            ],
            0x403000: [_dxref(), _dxref()],
        }

        self.entity_xrefs = {0: {0x402100}, 1: {0x402100}, 2: {0x402100}, 3: {0x402100}}

        # paths from entry reach the signal root at depth 2.
        self.paths = {EP: {0x402000: [[EP, 0x401800, 0x402000]],
                           0x402100: [[EP, 0x401800, 0x402000, 0x402100]]}}

        if with_llm:
            self.cluster_analysis = {
                "binary_category": "Backdoor",
                "binary_description": "A test backdoor.",
                "binary_report": "# Report\nSome narrative.",
                "clusters": {
                    "1": {
                        "label": "Injector",
                        "description": "Injects into a remote process.",
                        "function_prefix": "inj",
                        "relationships": "calls cluster.id.0002 for helpers",
                        "library_or_runtime": 0,
                        "mitre_attack": [
                            {"id": "T1055", "tactic": "Defense Evasion",
                             "name": "Process Injection", "rationale": "VAX+WPM."},
                        ],
                    },
                },
            }
        else:
            self.cluster_analysis = None

    def classify_functions(self):
        return {}

    def is_simple_api_thunk(self, ea):
        return False


def rva(ea):
    return f"0x{ea - IB:x}"


# --------------------------------------------------------------------------
# single-file anatomy
# --------------------------------------------------------------------------

def test_anatomy_builds_and_has_static_truth():
    d = build_anatomy(_XRefer())
    assert d["meta"]["has_llm_layer"] is True
    assert d["_end"]["sentinel"] == "XREFER_ANATOMY_EOF"
    # the injection cluster is a signal cluster reaching the danger floor
    roots = {c["root_rva"] for c in d["clusters"]}
    assert rva(0x402000) in roots
    inj = next(c for c in d["clusters"] if c["root_rva"] == rva(0x402000))
    assert inj["danger_floor"] == "process_injection"
    # llm label is fenced, never bare
    assert inj["llm"]["provenance"] == "llm"


# --------------------------------------------------------------------------
# tiered bundle: structure + provenance + cross-refs
# --------------------------------------------------------------------------

def test_bundle_structure_and_rva_encoding():
    b = build_agent_map(_XRefer())
    mp = b["map"]
    assert mp["schema"]["format"] == "xrefer-agent-map"
    assert mp["schema"]["has_llm_layer"] is True
    assert mp["image"]["sha256"] == "a" * 64
    assert mp["image"]["image_base_va"] == "0x400000"
    assert mp["image"]["entry_points_rva"] == [rva(EP)]

    # signal cluster gets a Tier-1 file; the library cluster does not.
    idx = {c["root_rva"]: c for c in mp["clusters_index"]}
    assert idx[rva(0x402000)]["detail_ref"] == f"clusters/{rva(0x402000)}.json"
    assert idx[rva(0x402000)]["is_library"] is False
    assert idx[rva(0x403000)]["is_library"] is True
    assert idx[rva(0x403000)]["library_kind"] == "llm"
    assert idx[rva(0x403000)]["detail_ref"] is None
    assert rva(0x402000) in b["clusters"]
    assert rva(0x403000) not in b["clusters"]


def test_investigation_queue_is_static_ranked():
    mp = build_agent_map(_XRefer())["map"]
    q = mp["investigation_queue"]
    assert [x["rank"] for x in q] == list(range(1, len(q) + 1))
    assert all(q[i]["score"] >= q[i + 1]["score"] for i in range(len(q) - 1))
    top = q[0]
    assert top["ref"] == rva(0x402000)
    assert top["danger_floor"] == "process_injection"
    # one_line is an llm hypothesis, tagged
    assert top["one_line"]["provenance"] == "llm"


def test_tier1_verify_against_points_at_real_functions():
    b = build_agent_map(_XRefer())
    detail = b["clusters"][rva(0x402000)]
    fn_rvas = {f["rva"] for f in detail["static"]["functions"]}
    va = detail["llm"]["verify_against"]["key_function_rvas"]
    assert va, "verify_against must name at least one function"
    assert set(va) <= fn_rvas
    # the artifact-bearing member (0x402100), not just the root, is the target
    assert rva(0x402100) in va
    # edges are preserved in the tiered detail (dropped only in the single file)
    assert [rva(0x402000), rva(0x402100)] in detail["static"]["edges"]


def test_relationship_run_refs_resolve_to_roots():
    b = build_agent_map(_XRefer())
    llm = b["clusters"][rva(0x402000)]["llm"]
    resolved = {r["run_ref"]: r["resolved_to_root_rva"] for r in llm["resolved_relationships"]}
    # "cluster.id.0002" in the prose -> cluster 2's root RVA
    assert resolved.get("cluster.id.0002") == rva(0x403000)
    assert llm["unresolved_run_ids"] == []


def test_reverse_index_and_reachability():
    b = build_agent_map(_XRefer())
    rev = b["indices"]["reverse_index.json"]
    # entity 0 (VirtualAllocEx) referenced by 0x402100
    assert rev["0"]["function_rvas"] == [rva(0x402100)]
    reach = b["indices"]["reachability.json"]
    assert reach[rva(0x402000)]["reachable"] is True
    assert reach[rva(0x402000)]["min_depth"] == 2


def test_category_and_origin_fallback_without_live_backend():
    # backend is dark (get_function_at -> None) and classify_functions -> {},
    # so category/origin must fall back to persisted cluster membership.
    b = build_agent_map(_XRefer())
    fi = b["indices"]["functions.json"]
    assert b["map"]["stats"]["backend_live"] is False
    row = fi[rva(0x402100)]
    assert row["category"] == "cluster_member"
    assert row["origin"] == "user"          # signal (non-library) cluster
    assert row["has_default_name"] is None  # needs live backend


def test_no_bare_llm_values_at_top_level():
    """Every LLM-derived scalar must be fenced (src==GUESS, provenance=='llm',
    or inside an llm/one_line/label block) — never a bare fact."""
    mp = build_agent_map(_XRefer())["map"]
    # binary verdict is explicitly llm-provenanced
    assert mp["binary"]["provenance"] == "llm"
    # mitre block is llm-provenanced
    assert mp["mitre"]["provenance"] == "llm"
    # clusters_index labels are wrapped
    for c in mp["clusters_index"]:
        if c["label"] is not None:
            assert c["label"]["provenance"] == "llm"


# --------------------------------------------------------------------------
# degrade: no LLM layer
# --------------------------------------------------------------------------

def test_degrade_without_llm_layer():
    b = build_agent_map(_XRefer(with_llm=False))
    mp = b["map"]
    assert mp["schema"]["has_llm_layer"] is False
    assert mp["binary"]["category"] is None
    assert mp["binary"]["report_present"] is False
    assert mp["mitre"] is None
    assert b["report_md"] is None
    # queue is still populated and purely static-scored
    assert mp["investigation_queue"], "static queue must survive without LLM"
    assert mp["investigation_queue"][0]["one_line"] is None
    # signal cluster detail carries no llm block but full static evidence
    detail = b["clusters"][rva(0x402000)]
    assert detail["llm"] is None
    assert detail["static"]["artifacts"]["apis"]


# --------------------------------------------------------------------------
# on-disk export: files + manifest integrity
# --------------------------------------------------------------------------

def test_export_writes_bundle_with_consistent_manifest(tmp_path):
    out = tmp_path / "bundle"
    export_agent_map(_XRefer(), str(out))

    mp = json.loads((out / "map.json").read_text())
    # every manifest entry exists and its byte size matches the file on disk
    for f in mp["manifest"]["tier1_files"] + mp["manifest"]["tier2"]:
        p = out / f["path"]
        assert p.exists(), f["path"]
        assert p.stat().st_size == f["bytes"]
    # every detail_ref resolves
    for c in mp["clusters_index"]:
        if c["detail_ref"]:
            assert (out / c["detail_ref"]).exists()
    # report.md present with the llm layer
    assert (out / "indices" / "report.md").exists()


def test_export_degrade_omits_report(tmp_path):
    out = tmp_path / "bundle_nollm"
    export_agent_map(_XRefer(with_llm=False), str(out))
    assert not (out / "indices" / "report.md").exists()
    mp = json.loads((out / "map.json").read_text())
    assert all(t["path"] != "indices/report.md" for t in mp["manifest"]["tier2"])
