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

"""Agent-facing "binary anatomy" export.

Projects xrefer's in-memory analysis (the master_struct fields on ``XRefer`` plus
``cluster_analysis``) into a portable, RVA-normalised, provenance-tiered JSON map
for an external malware-analysis agent (radare2 / format_binary).

Design contract (see the design mocks):
  * STATIC ground truth = bare values (RVAs, imports, xrefs, paths, capa,
    per-function category). The agent may state these as fact.
  * LLM hypotheses = objects tagged ``{"v": ..., "src": "xrefer_llm_guess"}``.
    The agent must confirm them by decompiling before citing.
  * Cluster identity = root-function RVA. Addresses are RVAs (va - image_base);
    the agent adds its own loader base.
  * Library demotion is provenance-split: ``static_lib`` (all members func_lib)
    is safe to collapse; ``llm_lib`` (the LLM library_or_runtime guess) is a
    budget lever, kept visible; any danger-floor-reaching cluster is force-kept.

Backend-agnostic and IDA-free: uses only the XRefer analyzer + backend
abstraction + stdlib, so it runs headless across any backend.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from xrefer.core.helpers import find_cluster_analysis, log

SCHEMA_VERSION = "2.0.0"
SENTINEL = "XREFER_ANATOMY_EOF"
GUESS = "xrefer_llm_guess"
MAX_SIGNAL_CLUSTERS = 40  # single-file cap; beyond this -> omission ledger + fallback advice

# Deterministic danger-floor API-name sets, matched on the lowercased API basename.
# STATIC: independent of any LLM flag. A cluster reaching one of these is never
# silently demoted, even if the LLM called it "library".
DANGER_FLOOR: Dict[str, Set[str]] = {
    "process_injection": {
        "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
        "queueuserapc", "setthreadcontext", "rtlcreateuserthread", "ntcreatethreadex",
        "virtualprotectex", "ntwritevirtualmemory", "ntprotectvirtualmemory",
    },
    "crypto": {
        "cryptencrypt", "cryptdecrypt", "cryptderivekey", "cryptacquirecontext",
        "bcryptencrypt", "bcryptdecrypt", "bcryptdecryptkey", "cryptgenkey", "cryptimportkey",
    },
    "net_exfil": {
        "winhttpsendrequest", "httpsendrequest", "httpsendrequesta", "httpsendrequestw",
        "internetopena", "internetopenw", "internetconnecta", "internetconnectw",
        "winhttpconnect", "winhttpopen", "wsasend", "urldownloadtofilew", "urldownloadtofilea",
    },
    "cred_access": {
        "lsaretrieveprivatedata", "credenumeratea", "credenumeratew", "samconnect",
        "openprocesstoken", "lookupaccountsida", "lsaenumerateaccountrights",
    },
}


def _llm(value: Any) -> Dict[str, Any]:
    """Wrap an LLM-derived value as a hypothesis so it is never bare."""
    return {"v": value, "src": GUESS}


def _api_basename(name: str) -> str:
    return (name or "").split(".")[-1].lower()


class _Builder:
    """Walks one analysed XRefer instance into the anatomy dict."""

    def __init__(self, x: Any):
        self.x = x
        self.ib: int = int(x.image_base)
        self.ep: Optional[int] = x.current_analysis_ep
        self.ca: Dict[str, Any] = getattr(x, "cluster_analysis", None) or {}
        self.entities = x.entities
        self.gx = x.global_xrefs
        self.DIRECT = x.DIRECT_XREFS
        self.INDIRECT = x.INDIRECT_XREFS
        try:
            self.placements = x.classify_functions()
        except Exception as e:  # pragma: no cover - defensive
            log(f"[agent_map] classify_functions failed ({e}); origin left best-effort")
            self.placements = {}
        # reachable-node set for orphan detection
        self._reach_nodes: Set[int] = set()
        if self.ep is not None:
            for plist in (x.paths.get(self.ep, {}) or {}).values():
                for p in plist:
                    self._reach_nodes.update(p)

    # ---------------- addressing ----------------
    def rva(self, ea: int) -> str:
        return f"0x{(int(ea) - self.ib) & 0xFFFFFFFFFFFFFFFF:x}"

    # ---------------- per-function static ----------------
    def _category(self, ea: int) -> str:
        p = self.placements.get(ea)
        return getattr(p, "category", None) or "cluster_member"

    def _entry(self, ea: int, idx: int) -> Dict[str, Any]:
        return self.gx.get(ea, {})[idx] if ea in self.gx else {}

    def _indirect_count(self, ea: int) -> int:
        try:
            ind = self._entry(ea, self.INDIRECT)
            return sum(len(ind.get(k, ())) for k in ("libs", "imports", "strings", "capa", "api_trace"))
        except Exception:
            return 0

    def _direct_artifacts(self, ea: int) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {"apis": [], "strings": [], "libs": [], "capa": [], "api_trace": []}
        d = self._entry(ea, self.DIRECT)
        if not d:
            return out
        for setkey, eakey, outkey in (
            ("imports", "imports_ea", "apis"), ("strings", "strings_ea", "strings"),
            ("libs", "libs_ea", "libs"), ("capa", "capa_ea", "capa"),
            ("api_trace", "api_trace_ea", "api_trace"),
        ):
            for idx in sorted(d.get(setkey, ())):
                try:
                    name = self.entities[idx][1]
                except Exception:
                    name = str(idx)
                sites = sorted(self.rva(a) for a in d.get(eakey, {}).get(idx, ()))
                out[outkey].append({"entity_idx": idx, "name": name, "call_site_rvas": sites})
        return {k: v for k, v in out.items() if v}

    # ---------------- cluster-level static ----------------
    def _import_basenames(self, cluster: Any) -> Set[str]:
        names: Set[str] = set()
        for ea in cluster.nodes:
            for xt in (self.DIRECT, self.INDIRECT):
                for idx in self._entry(ea, xt).get("imports", ()):
                    try:
                        names.add(_api_basename(self.entities[idx][1]))
                    except Exception:
                        pass
        return names

    def _danger_floor(self, cluster: Any) -> Optional[str]:
        names = self._import_basenames(cluster)
        for cat, sig in DANGER_FLOOR.items():
            if names & sig:
                return cat
        return None

    def _static_lib(self, cluster: Any) -> bool:
        nodes = list(cluster.nodes)
        return bool(nodes) and all(self._category(ea) == "func_lib" for ea in nodes)

    def _reachability(self, root_ea: int) -> Dict[str, Any]:
        plist = (self.x.paths.get(self.ep, {}) or {}).get(root_ea) if self.ep is not None else None
        if not plist:
            return {"reachable": False, "min_depth": None, "via_path_rvas": [], "n_paths": 0}
        shortest = min(plist, key=len)
        return {
            "reachable": True, "min_depth": len(shortest) - 1,
            "via_path_rvas": [self.rva(e) for e in shortest], "n_paths": len(plist),
        }

    def _cluster_static(self, cluster: Any) -> Dict[str, Any]:
        funcs = []
        for ea in sorted(cluster.nodes):
            arts = self._direct_artifacts(ea)
            funcs.append({
                "rva": self.rva(ea),
                "category": self._category(ea),
                "is_simple_api_thunk": self._safe_thunk(ea),
                "indirect_artifact_count": self._indirect_count(ea),
                "artifacts": arts,
            })
        edges = [[self.rva(s), self.rva(t)] for (s, t) in getattr(cluster, "edges", [])]
        subrefs = [{"at_node_rva": self.rva(n), "child_cluster_id": cid}
                   for n, cid in getattr(cluster, "cluster_refs", {}).items()]
        return {"functions": funcs, "edges": edges, "subcluster_refs": subrefs}

    def _safe_thunk(self, ea: int) -> bool:
        try:
            return bool(self.x.is_simple_api_thunk(ea))
        except Exception:
            return False

    # ---------------- LLM overlay ----------------
    def _cluster_llm(self, cluster: Any) -> Optional[Dict[str, Any]]:
        analysis = find_cluster_analysis(self.ca, cluster.id) if self.ca else None
        if not analysis:
            return None
        get = (lambda k: analysis.get(k)) if isinstance(analysis, dict) else (lambda k: getattr(analysis, k, None))
        raw_mitre = get("mitre_attack") or []
        mitre = []
        for e in raw_mitre:
            ed = e.model_dump() if hasattr(e, "model_dump") else (e if isinstance(e, dict) else None)
            if not ed or not ed.get("id"):
                continue
            mitre.append({"id": str(ed.get("id", "")), "tactic": str(ed.get("tactic", "")),
                          "name": str(ed.get("name", "")), "rationale": str(ed.get("rationale", ""))})
        # verify_against RVAs come from the STATIC side (cluster members), never the prose.
        va = [self.rva(ea) for ea in sorted(cluster.nodes)][:6]
        return {
            "provenance": "llm",
            "label": get("label"),
            "description": get("description"),
            "function_prefix": get("function_prefix"),
            "relationships": get("relationships"),
            "mitre": mitre,
            "verify_against": {"key_function_rvas": va},
            "verify": "Confirm by r2_decompile'ing the key_function_rvas at their call_site_rvas before citing.",
        }

    # ---------------- assembly ----------------
    def build(self) -> Dict[str, Any]:
        has_llm = bool(self.ca)
        clusters_out: List[Dict[str, Any]] = []
        queue: List[Dict[str, Any]] = []
        omitted_notable: List[Dict[str, Any]] = []
        static_lib_roots: List[str] = []
        llm_lib_demoted: List[Dict[str, Any]] = []
        promoted_out: List[str] = []

        # rank all top-level + sub clusters flat by static score, then cap.
        all_clusters = list(self._iter_clusters())
        scored = []
        for cl in all_clusters:
            static_lib = self._static_lib(cl)
            danger = self._danger_floor(cl)
            llm_lib = bool(getattr(cl, "is_library", False)) and not static_lib
            score, why = self._score(cl, danger)
            scored.append((score, cl, static_lib, llm_lib, danger, why))
        scored.sort(key=lambda t: t[0], reverse=True)

        shown = 0
        for score, cl, static_lib, llm_lib, danger, why in scored:
            root_rva = self.rva(cl.root_node)
            # library handling
            if static_lib and danger is None:
                static_lib_roots.append(root_rva)
                continue
            if llm_lib and danger is None:
                llm_lib_demoted.append({"root_rva": root_rva,
                                        "reason": _llm(True),
                                        "note": "LLM library_or_runtime guess; you MAY skip to save budget but it is NOT triaged."})
                continue
            promoted = (static_lib or llm_lib) and danger is not None
            if promoted:
                promoted_out.append(root_rva)
            # cap: signal clusters beyond MAX go to the omission ledger (danger-floor ones flagged)
            if shown >= MAX_SIGNAL_CLUSTERS:
                if danger is not None:
                    omitted_notable.append({"rva": root_rva, "why": f"truncated; statically reaches danger floor: {danger}", "static": True})
                continue
            shown += 1
            node = {
                "root_rva": root_rva,
                "run_ref": f"cluster.id.{cl.id_str}",
                "parent_cluster_id": cl.parent_cluster_id,
                "static_lib": static_lib,
                "llm_lib": _llm(True) if llm_lib else None,
                "danger_floor": danger,
                "promoted_from_noise": promoted or None,
                "static": self._cluster_static(cl),
                "reachability": self._reachability(cl.root_node),
                "llm": self._cluster_llm(cl) if has_llm else None,
            }
            clusters_out.append(node)
            queue.append({
                "kind": "cluster", "ref_rva": root_rva, "static_score": round(score, 3),
                "danger_floor": danger, "promoted_from_noise": promoted or None,
                "why": why, "first_move": f"r2_decompile {root_rva}", "done": False,
            })

        queue.sort(key=lambda q: q["static_score"], reverse=True)
        for i, q in enumerate(queue, 1):
            q["rank"] = i

        data: Dict[str, Any] = {
            "_readme": self._readme(len(clusters_out), len(all_clusters), len(static_lib_roots), len(llm_lib_demoted)),
            "meta": {"generator": "xrefer", "schema_version": SCHEMA_VERSION, "has_llm_layer": has_llm,
                     "target_workflow": "format_binary (persistent radare2 project, sha256-keyed)"},
            "bind_check": self._bind_check(),
            "image": {"format": getattr(self.x.lang, "format", None) if getattr(self.x, "lang", None) else None,
                      "image_base": f"0x{self.ib:x}",
                      "entry_points_rva": [self.rva(self.ep)] if self.ep is not None else []},
            "entry_anchor": {"application_roots_rva": [c["root_rva"] for c in clusters_out[:5]],
                             "read_first_rva": [queue[0]["ref_rva"]] if queue else []},
            "verdict": {"claim": {"v": self.ca.get("binary_category") if has_llm else None, "src": GUESS,
                                  "verdict": None,
                                  "description": _llm(self.ca.get("binary_description")) if has_llm else None}},
            "investigation_queue": queue,
            "clusters": clusters_out,
            "noise": {"static_lib_count": len(static_lib_roots),
                      "static_lib_sample_rvas": static_lib_roots[:3],
                      "llm_lib_demoted": llm_lib_demoted, "promoted_out": promoted_out},
            "coverage": {"omitted": {"clusters": max(0, len(all_clusters) - len(clusters_out) - len(static_lib_roots) - len(llm_lib_demoted)),
                                     "notable_rvas": omitted_notable,
                                     "note": "You may NOT conclude 'benign'/'complete' until every notable_rva is r2-triaged."}},
            "entities": self._entities_catalog(),
            "report_scaffold": self._report_scaffold(),
            "_end": {"sentinel": SENTINEL, "declared_bytes": 0, "part": "1/1"},
        }
        return data

    def _iter_clusters(self):
        stack = list(self.x.clusters or [])
        while stack:
            c = stack.pop()
            yield c
            stack.extend(getattr(c, "subclusters", []) or [])

    def _score(self, cluster: Any, danger: Optional[str]):
        why: List[str] = []
        score = 0.0
        if danger:
            score += 3.0
            why.append(f"reaches danger floor: {danger}")
        # capa density
        capa = 0
        max_ind = 0
        for ea in cluster.nodes:
            capa += len(self._entry(ea, self.DIRECT).get("capa", ()))
            max_ind = max(max_ind, self._indirect_count(ea))
        if capa:
            score += 0.5 * capa
            why.append(f"{capa} capa match(es)")
        if max_ind:
            score += min(max_ind, 60) / 60.0
            why.append(f"INDIRECT-hub: gates up to {max_ind} downstream artifacts")
        reach = self._reachability(cluster.root_node)
        if reach["reachable"]:
            score += 1.0
            score += max(0.0, (10 - (reach["min_depth"] or 0))) / 20.0
            why.append(f"reachable from entry at depth {reach['min_depth']}")
        else:
            why.append("not reachable from entry (orphan-like)")
        return score, why

    def _entities_catalog(self) -> List[Dict[str, Any]]:
        out = []
        for idx, ent in enumerate(self.entities):
            try:
                name, type_id = ent[1], ent[2]
            except Exception:
                continue
            kind = {1: "lib", 2: "api", 3: "string", 4: "capa", 5: "api_trace"}.get(type_id, str(type_id))
            xc = 0
            try:
                xc = len(self.x.entity_xrefs.get(idx, ()))
            except Exception:
                pass
            out.append({"idx": idx, "kind": kind, "name": name, "xref_count": xc})
        return out

    def _bind_check(self) -> Dict[str, Any]:
        sha = None
        try:
            with open(self.x._backend.path, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()
        except Exception as e:
            log(f"[agent_map] sha256 unavailable: {e}")
        anchor_hex = None
        try:
            b = self.x._backend.read_bytes(self.ep, 12)
            if b:
                anchor_hex = bytes(b).hex()
        except Exception:
            pass
        return {"sha256": sha, "image_base": f"0x{self.ib:x}", "baddr_is_assumed": True,
                "check_anchor_rva": self.rva(self.ep) if self.ep is not None else None,
                "expected_bytes_hex": anchor_hex,
                "recipe": "r2_addr = r2_baddr + rva; read your real baddr, do not assume it equals image_base.",
                "on_mismatch": "REFUSE: wrong sample or wrong base. Do not r2_decompile these RVAs or apply an annotation."}

    def _readme(self, shown: int, total: int, static_lib: int, llm_lib: int) -> Dict[str, Any]:
        return {
            "format": "xrefer-binary-anatomy",
            "what": ("A single-file investigation PLAN produced by xrefer. NOT a finished analysis and "
                     "contains NO decompiled code. Ranks where to point radare2 first; xrefer's "
                     "interpretations are null-verdict hypotheses you must confirm by reading the body."),
            "provenance": ("BARE values = STATIC ground truth (RVAs, imports, xrefs, paths, capa, "
                           "category=='func_lib'/is_simple_api_thunk). Objects with src=='xrefer_llm_guess' = "
                           "HYPOTHESIS. NOTE: cluster is_library/llm_lib and per-function origin are LLM-derived; "
                           "the static library signal is category=='func_lib'. type_id: 1=lib 2=api 3=string 4=capa 5=api_trace."),
            "capability_gate_applies": True,
            "counts": {"clusters_shown": shown, "clusters_total": total,
                       "clusters_static_lib": static_lib, "clusters_llm_lib": llm_lib},
        }

    def _report_scaffold(self) -> Dict[str, Any]:
        return {
            "output_contract": [
                "Emit a coverage header FIRST, computed from the functions you actually r2_decompile'd.",
                "Every capability sentence MUST quote the decompiled body excerpt at its cited RVA.",
                "Attribute every xrefer hypothesis ('xrefer proposed X; I confirmed via r2_decompile @RVA' or 'UNCONFIRMED').",
                "Do NOT write 'benign'/completeness while any coverage.omitted.notable_rvas RVA is unread.",
                "Speak MITRE technique-ids for the TTP section.",
            ],
        }


def build_anatomy(xrefer: Any) -> Dict[str, Any]:
    """Return the anatomy dict for an analysed XRefer instance."""
    return _Builder(xrefer).build()


def export_anatomy(xrefer: Any, out_path: str) -> str:
    """Write the single-file anatomy JSON to ``out_path``; returns the path."""
    data = build_anatomy(xrefer)
    # fixed-point declared_bytes so the integrity trailer is exact
    data["_end"]["declared_bytes"] = 0
    raw = json.dumps(data, indent=2)
    cur = len(raw.encode("utf-8"))
    n = cur
    for _ in range(6):
        n = cur - 1 + len(str(n))
    data["_end"]["declared_bytes"] = n
    raw = json.dumps(data, indent=2)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    log(f"[agent_map] wrote {out_path} ({len(raw.encode('utf-8'))} bytes, "
        f"{len(data['clusters'])} signal clusters, has_llm={data['meta']['has_llm_layer']})")
    return out_path
