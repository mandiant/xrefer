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
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from xrefer.core.helpers import find_cluster_analysis, log

SCHEMA_VERSION = "2.0.0"
# Cluster reference token the LLM is instructed to emit in prose relationships
# (dspy_modules.py:633 "Always follow the format cluster.id.xxxx"). We resolve
# these to root RVAs at export time so the agent never has to.
_RUN_REF_RE = re.compile(r"cluster\.id\.(\d+)")
SENTINEL = "XREFER_ANATOMY_EOF"
GUESS = "xrefer_llm_guess"
MAX_SIGNAL_CLUSTERS = 15    # single-file must stay pasteable; beyond this -> omission ledger / tiered bundle
MAX_FUNCS_PER_CLUSTER = 6   # curation: keep the most artifact-dense functions per cluster (+ root)
MAX_CALL_SITES = 3          # curation: call-site RVAs kept per artifact
MAX_ARTIFACTS_PER_TYPE = 5  # curation: apis/strings/capa/api_trace kept per function
MAX_STR_LEN = 80            # curation: truncate long string/artifact names

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
        # entity indices actually cited by shown functions (drives a lean entities catalog)
        self._referenced: Set[int] = set()
        # reachable-node set for orphan detection
        self._reach_nodes: Set[int] = set()
        if self.ep is not None:
            for plist in (x.paths.get(self.ep, {}) or {}).values():
                for p in plist:
                    self._reach_nodes.update(p)
        # Resolve per-run cluster ids -> root RVA once (identity is the root; the
        # numeric/id_str token is only resolvable at export). Covers subclusters.
        self._id_to_root: Dict[int, int] = {}
        self._idstr_to_root: Dict[str, int] = {}
        for c in self._iter_clusters():
            try:
                self._id_to_root[c.id] = c.root_node
                self._idstr_to_root[str(c.id_str)] = c.root_node
            except Exception:
                pass
        # Function-object cache for has_default_name / name (backend-abstracted,
        # still IDA-free — Address is a plain int subclass on the base backend).
        self._fn_cache: Dict[int, Any] = {}
        # Persisted-cluster fallbacks for per-function category/origin. classify_functions()
        # (and the live backend function queries it needs) only work when the backend is
        # fully live (in-IDA). In a headless load-from-cache export the backend can be dark,
        # so we derive category (cluster_member vs shared) and origin (user vs library, via
        # the LLM is_library verdict) from the persisted cluster membership — all ground
        # truth from the .xrefer pickle. Live placements always take precedence.
        self._member_top: Dict[int, int] = {}
        self._member_lib_only: Dict[int, bool] = {}
        for c in (x.clusters or []):
            lib = bool(getattr(c, "is_library", False))
            seen: Set[int] = set()
            stack = [c]
            while stack:
                cc = stack.pop()
                seen |= set(cc.nodes)
                stack.extend(getattr(cc, "subclusters", None) or [])
            for n in seen:
                self._member_top[n] = self._member_top.get(n, 0) + 1
                self._member_lib_only[n] = self._member_lib_only.get(n, True) and lib
        # One-time probe: are live per-function backend queries available? They are
        # in-IDA; a headless load-from-cache backend can be dark. Gates has_default_name
        # (skips hundreds of doomed get_function_at calls) and is surfaced in the map so
        # the consumer knows when this field is unavailable rather than false.
        self._backend_live = False
        try:
            from xrefer.backend.base import Address
            probe = None
            for c in (x.clusters or []):
                if c.nodes:
                    probe = next(iter(c.nodes))
                    break
            if probe is None and self.ep is not None:
                probe = self.ep
            if probe is None and self.gx:
                probe = next(iter(self.gx))
            if probe is not None:
                self._backend_live = self.x._backend.get_function_at(Address(int(probe))) is not None
        except Exception:
            self._backend_live = False

    # ---------------- addressing ----------------
    def rva(self, ea: int) -> str:
        return f"0x{(int(ea) - self.ib) & 0xFFFFFFFFFFFFFFFF:x}"

    # ---------------- per-function static ----------------
    def _category(self, ea: int) -> str:
        p = self.placements.get(ea)
        cat = getattr(p, "category", None) if p else None
        if cat:
            return cat
        # Fallback from persisted membership (func_lib needs the live backend).
        c = self._member_top.get(ea, 0)
        return "shared" if c >= 2 else "cluster_member"

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
        # Curation: drop library refs (low signal); keep apis/strings/capa/api_trace, capped per type.
        for setkey, eakey, outkey in (
            ("imports", "imports_ea", "apis"), ("strings", "strings_ea", "strings"),
            ("capa", "capa_ea", "capa"), ("api_trace", "api_trace_ea", "api_trace"),
        ):
            idxs = sorted(d.get(setkey, ()))
            for idx in idxs[:MAX_ARTIFACTS_PER_TYPE]:
                try:
                    name = str(self.entities[idx][1])
                except Exception:
                    name = str(idx)
                if len(name) > MAX_STR_LEN:
                    name = name[:MAX_STR_LEN] + "…"
                sites = sorted(self.rva(a) for a in d.get(eakey, {}).get(idx, ()))
                entry = {"entity_idx": idx, "name": name, "call_site_rvas": sites[:MAX_CALL_SITES]}
                if len(sites) > MAX_CALL_SITES:
                    entry["call_sites_omitted"] = len(sites) - MAX_CALL_SITES
                out[outkey].append(entry)
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
        root = cluster.root_node
        raw = []
        for ea in sorted(cluster.nodes):
            arts = self._direct_artifacts(ea)
            n_direct = sum(len(v) for v in arts.values())
            raw.append((ea, arts, n_direct))
        # Curation (single-file must stay pasteable): keep the root + artifact-bearing
        # functions, densest first, capped. Pure call-graph filler is dropped (the agent
        # decompiles the root and follows edges itself).
        keep = [t for t in raw if t[2] > 0 or t[0] == root]
        keep.sort(key=lambda t: (t[0] != root, -t[2], -self._indirect_count(t[0])))
        shown = keep[:MAX_FUNCS_PER_CLUSTER]
        funcs = []
        for ea, arts, _n in shown:
            for lst in arts.values():
                for a in lst:
                    self._referenced.add(a["entity_idx"])
            funcs.append({
                "rva": self.rva(ea),
                "category": self._category(ea),
                "is_simple_api_thunk": self._safe_thunk(ea),
                "indirect_artifact_count": self._indirect_count(ea),
                "artifacts": arts,
            })
        # Edges dropped for single-file (the agent recovers the call graph with r2_callees);
        # the cluster grouping + subcluster refs are the non-reproducible part we keep.
        subrefs = [{"at_node_rva": self.rva(n), "child_cluster_id": cid}
                   for n, cid in getattr(cluster, "cluster_refs", {}).items()]
        return {"functions": funcs, "function_count": len(cluster.nodes),
                "artifact_bearing_shown": len(funcs),
                "functions_omitted": max(0, len(keep) - len(shown)),
                "subcluster_refs": subrefs}

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
        # Lean: only entities actually cited by a shown function (not the whole ~3k catalog).
        out = []
        for idx in sorted(self._referenced):
            try:
                ent = self.entities[idx]
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

    # =====================================================================
    # TIERED BUNDLE ("xrefer-agent-map")
    # ---------------------------------------------------------------------
    # Same static-truth/llm-hypothesis discipline as the single file, but the
    # FULL uncurated projection split across lazy-loaded files: a Tier-0
    # map.json (verdict + ranked queue + indexes-of-everything), one Tier-1
    # clusters/<root_rva>.json per SIGNAL cluster (full evidence incl. edges),
    # and Tier-2 indices/ (reverse index, reachability, per-function
    # classification, full entity catalog, LLM report). Nothing is capped —
    # the agent fetches only what a given pivot needs.
    # =====================================================================

    # ---- per-function projections (uncapped) ----
    def _fn(self, ea: int) -> Any:
        """Cached backend Function object (or None). IDA-free: Address is a
        plain int subclass on the backend abstraction."""
        if ea in self._fn_cache:
            return self._fn_cache[ea]
        fn = None
        try:
            from xrefer.backend.base import Address
            fn = self.x._backend.get_function_at(Address(int(ea)))
        except Exception:
            fn = None
        self._fn_cache[ea] = fn
        return fn

    def _has_default_name(self, ea: int) -> Optional[bool]:
        if not self._backend_live:
            return None
        fn = self._fn(ea)
        if fn is None:
            return None
        try:
            return bool(fn.has_default_name)
        except Exception:
            return None

    def _origin(self, ea: int) -> Optional[str]:
        p = self.placements.get(ea)
        o = getattr(p, "origin", None) if p else None
        if o:
            return o
        # Fallback: library only if EVERY containing cluster is is_library (mirrors
        # classify_functions._origin), else user. None only for unclustered functions.
        if ea in self._member_lib_only:
            return "library" if self._member_lib_only[ea] else "user"
        return None

    def _func_row(self, ea: int) -> Dict[str, Any]:
        return {
            "rva": self.rva(ea),
            "category": self._category(ea),
            "origin": self._origin(ea),
            "has_default_name": self._has_default_name(ea),
            "is_simple_api_thunk": self._safe_thunk(ea),
            "indirect_artifact_count": self._indirect_count(ea),
        }

    def _typed_counts(self, ea: int, xt: int) -> Dict[str, int]:
        e = self._entry(ea, xt)
        return {
            "apis": len(e.get("imports", ()) or ()),
            "strings": len(e.get("strings", ()) or ()),
            "libs": len(e.get("libs", ()) or ()),
            "capa": len(e.get("capa", ()) or ()),
            "api_trace": len(e.get("api_trace", ()) or ()),
        }

    # ---- cluster-level artifacts (uncapped, merged per entity) ----
    def _cluster_artifacts_full(self, cluster: Any) -> Dict[str, List[Dict[str, Any]]]:
        merged: Dict[str, Dict[int, Dict[str, Any]]] = {
            "apis": {}, "strings": {}, "libs": {}, "capa": {}, "api_trace": {},
        }
        for ea in cluster.nodes:
            d = self._entry(ea, self.DIRECT)
            if not d:
                continue
            for setkey, eakey, outkey in (
                ("imports", "imports_ea", "apis"), ("strings", "strings_ea", "strings"),
                ("libs", "libs_ea", "libs"), ("capa", "capa_ea", "capa"),
                ("api_trace", "api_trace_ea", "api_trace"),
            ):
                for idx in d.get(setkey, ()):
                    try:
                        name = str(self.entities[idx][1])
                    except Exception:
                        name = str(idx)
                    slot = merged[outkey].get(idx)
                    if slot is None:
                        slot = {"entity_idx": idx, "name": name, "call_site_rvas": set()}
                        merged[outkey][idx] = slot
                    slot["call_site_rvas"].update(self.rva(a) for a in d.get(eakey, {}).get(idx, ()))
                    self._referenced.add(idx)
        out: Dict[str, List[Dict[str, Any]]] = {}
        for k, m in merged.items():
            rows = []
            for idx in sorted(m):
                row = m[idx]
                row["call_site_rvas"] = sorted(row["call_site_rvas"])
                rows.append(row)
            out[k] = rows
        return out

    def _artifact_bearing(self, cluster: Any) -> List[int]:
        out = []
        for ea in sorted(cluster.nodes):
            d = self._entry(ea, self.DIRECT)
            if d and any(d.get(k) for k in ("imports", "strings", "capa", "api_trace")):
                out.append(ea)
        return out

    def _resolve_run_refs(self, text: str) -> Tuple[List[Dict[str, str]], List[str]]:
        """Extract cluster.id.NNNN tokens from an LLM relationships string and
        resolve each to a root RVA. Surfaces unresolved ids honestly."""
        resolved: List[Dict[str, str]] = []
        unresolved: List[str] = []
        seen: Set[str] = set()
        for m in _RUN_REF_RE.finditer(text or ""):
            tok = m.group(1)
            if tok in seen:
                continue
            seen.add(tok)
            root = self._idstr_to_root.get(tok)
            if root is None:
                try:
                    root = self._id_to_root.get(int(tok))
                except Exception:
                    root = None
            run_ref = f"cluster.id.{tok}"
            if root is None:
                unresolved.append(run_ref)
            else:
                resolved.append({"run_ref": run_ref, "resolved_to_root_rva": self.rva(root)})
        return resolved, unresolved

    def _cluster_llm_full(self, cluster: Any, artifacts: Dict[str, List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
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
        rel_str = str(get("relationships") or "").strip()
        resolved, unresolved = self._resolve_run_refs(rel_str)
        bearing = [self.rva(ea) for ea in self._artifact_bearing(cluster)][:8] or [self.rva(cluster.root_node)]
        key_idxs = sorted({row["entity_idx"] for k in artifacts for row in artifacts[k]})[:12]
        return {
            "provenance": "llm",
            "label": get("label"),
            "description": get("description"),
            "function_prefix": get("function_prefix"),
            "relationships": rel_str or None,
            "resolved_relationships": resolved,
            "unresolved_run_ids": unresolved,
            "mitre": mitre,
            "verify_against": {"key_function_rvas": bearing, "key_artifact_entity_idxs": key_idxs},
            "verify": ("r2_decompile the key_function_rvas at their static.artifacts call_site_rvas and "
                       "confirm the behaviour in the body before citing this label or applying any rename."),
        }

    def _cluster_detail(self, rec: Dict[str, Any], has_llm: bool) -> Dict[str, Any]:
        cl = rec["cl"]
        artifacts = self._cluster_artifacts_full(cl)
        funcs = [self._func_row(ea) for ea in sorted(cl.nodes)]
        edges = sorted([[self.rva(a), self.rva(b)] for a, b in (getattr(cl, "edges", None) or [])])
        subrefs = []
        for node_ea, child_id in (getattr(cl, "cluster_refs", None) or {}).items():
            child_root = self._id_to_root.get(child_id)
            subrefs.append({
                "at_node_rva": self.rva(node_ea),
                "child_run_ref": f"cluster.id.{child_id:04d}",
                "child_root_rva": self.rva(child_root) if child_root is not None else None,
                "note": "static call linkage from FunctionalCluster.cluster_refs (trustworthy edge; not an LLM guess)",
            })
        return {
            "identity": {
                "root_rva": rec["root_rva"], "run_ref": f"cluster.id.{cl.id_str}",
                "parent_root_rva": rec["parent_root_rva"], "is_library": rec["is_lib"],
                "library_kind": rec["library_kind"], "danger_floor": rec["danger"],
                "promoted_from_noise": rec["promoted"] or None,
            },
            "static": {"functions": funcs, "edges": edges, "subcluster_refs": subrefs, "artifacts": artifacts},
            "llm": self._cluster_llm_full(cl, artifacts) if has_llm else None,
        }

    # ---- cluster classification (shared by index / queue / tier-1) ----
    def _classify(self) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for cl in self._iter_clusters():
            static_lib = self._static_lib(cl)
            danger = self._danger_floor(cl)
            llm_lib = bool(getattr(cl, "is_library", False)) and not static_lib
            is_lib = static_lib or llm_lib
            promoted = is_lib and danger is not None
            signal = (not is_lib) or promoted
            score, why = self._score(cl, danger)
            pid = getattr(cl, "parent_cluster_id", None)
            proot = self._id_to_root.get(pid) if pid is not None else None
            records.append({
                "cl": cl, "root_ea": cl.root_node, "root_rva": self.rva(cl.root_node),
                "static_lib": static_lib, "llm_lib": llm_lib,
                "library_kind": ("static" if static_lib else ("llm" if llm_lib else None)),
                "is_lib": is_lib, "danger": danger, "promoted": promoted, "signal": signal,
                "score": score, "why": why,
                "parent_root_rva": self.rva(proot) if proot is not None else None,
            })
        records.sort(key=lambda r: r["score"], reverse=True)
        return records

    # ---- Tier-0 map.json blocks ----
    def _clusters_index(self, records: List[Dict[str, Any]], has_llm: bool) -> List[Dict[str, Any]]:
        rows = []
        for r in records:
            cl = r["cl"]
            llm = self._cluster_llm_full(cl, {}) if (has_llm and r["signal"]) else None
            tactics = sorted({m["tactic"] for m in (llm or {}).get("mitre", []) if m.get("tactic")}) if llm else []
            rows.append({
                "root_rva": r["root_rva"], "run_ref": f"cluster.id.{cl.id_str}",
                "is_library": r["is_lib"], "library_kind": r["library_kind"],
                "danger_floor": r["danger"], "promoted_from_noise": r["promoted"] or None,
                "node_count": len(cl.nodes), "subcluster_count": len(getattr(cl, "subclusters", None) or []),
                "parent_root_rva": r["parent_root_rva"],
                "mitre_tactics": tactics,
                "label": ({"provenance": "llm", "text": (llm or {}).get("label")} if llm and (llm or {}).get("label") else None),
                "function_prefix": ({"provenance": "llm", "text": (llm or {}).get("function_prefix")} if llm and (llm or {}).get("function_prefix") else None),
                "detail_ref": (f"clusters/{r['root_rva']}.json" if r["signal"] else None),
            })
        return rows

    def _investigation_queue(self, records: List[Dict[str, Any]], orphans: List[Dict[str, Any]], has_llm: bool) -> List[Dict[str, Any]]:
        items = []
        for r in records:
            if not r["signal"]:
                continue
            cl = r["cl"]
            llm = self._cluster_llm_full(cl, {}) if has_llm else None
            bearing = self._artifact_bearing(cl)
            focus = self.rva(bearing[0]) if bearing else r["root_rva"]
            items.append({
                "kind": "cluster", "ref": r["root_rva"], "score": round(r["score"], 3),
                "why": r["why"], "danger_floor": r["danger"], "promoted_from_noise": r["promoted"] or None,
                "one_line": ({"provenance": "llm", "text": (llm or {}).get("label")} if llm and (llm or {}).get("label") else None),
                "detail_ref": f"clusters/{r['root_rva']}.json",
                "first_move": f"open clusters/{r['root_rva']}.json; r2_decompile {focus} at its static.artifacts call_site_rvas",
            })
        for o in orphans:
            items.append({
                "kind": "orphan", "ref": o["func_rva"], "score": 0.5,
                "why": ["artifact-bearing but UNREACHABLE from entry (likely callback/TLS/export)"],
                "danger_floor": None, "promoted_from_noise": None, "one_line": None,
                "detail_ref": None, "first_move": o["next"],
            })
        items.sort(key=lambda q: q["score"], reverse=True)
        for i, q in enumerate(items, 1):
            q["rank"] = i
        return items

    def _mitre_killchain(self, has_llm: bool) -> Optional[Dict[str, Any]]:
        if not has_llm:
            return None
        try:
            from xrefer.core.mitre import (MITRE_TACTIC_ORDER, aggregate_mitre_matrix, mitre_attack_url)
            matrix = aggregate_mitre_matrix(self.x.clusters or [], self.ca, hide_library=True)
        except Exception as e:
            log(f"[agent_map] mitre aggregation failed: {e}")
            return None
        tactics = []
        for group in matrix.tactics:
            try:
                order_index = MITRE_TACTIC_ORDER.index(group.tactic)
            except ValueError:
                order_index = len(MITRE_TACTIC_ORDER)
            techs = []
            for t in group.techniques:
                groundings, resolved = [], []
                for g in t.groundings:
                    root = self._id_to_root.get(g.cluster_id)
                    rrva = self.rva(root) if root is not None else None
                    groundings.append({"cluster_root_rva": rrva, "cluster_label": g.cluster_label, "rationale": g.rationale})
                    if rrva:
                        resolved.append(rrva)
                techs.append({"id": t.id, "name": t.name, "url": mitre_attack_url(t.id),
                              "groundings": groundings, "cluster_root_rvas": sorted(set(resolved))})
            tactics.append({"tactic": group.tactic, "order_index": order_index, "techniques": techs})
        return {
            "provenance": "llm",
            "verify": ("MITRE mappings are LLM-extracted; rationale is the ONLY evidence link. r2_decompile "
                       "each grounding cluster to confirm before repeating a technique claim."),
            "exporters_available": ["navigator", "stix", "csv"],
            "tactics_kill_chain_order": tactics,
            "empty_tactics": list(matrix.uncovered_tactics),
        }

    def _orphans_index(self) -> List[Dict[str, Any]]:
        if self.ep is None or not self._reach_nodes:
            return []
        members: Set[int] = set()
        for cl in self._iter_clusters():
            members.update(cl.nodes)
        out = []
        for ea in sorted(members):
            if ea in self._reach_nodes:
                continue
            d = self._entry(ea, self.DIRECT)
            if not d:
                continue
            carried = sorted(set(d.get("imports", ())) | set(d.get("strings", ())) |
                             set(d.get("capa", ())) | set(d.get("api_trace", ())))
            if not carried:
                continue
            out.append({"func_rva": self.rva(ea), "carried_artifacts": carried[:20],
                        "why": "artifact_bearing_no_entry_path",
                        "next": f"r2_xrefs_to {self.rva(ea)} to find the caller r2's static pass missed"})
        return out

    # ---- Tier-2 index files ----
    def _reverse_index(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "_comment": ("entity_xrefs reverse index (provenance: static) = PRECOMPUTED r2_xrefs_to for every "
                         "artifact. key = entity_idx (see entities.json); value.function_rvas = every function "
                         "that references it. r2 address = r2_baddr + rva."),
        }
        for idx, funcs in (self.x.entity_xrefs or {}).items():
            if not funcs:
                continue
            out[str(idx)] = {"function_rvas": sorted(self.rva(ea) for ea in funcs)}
        return out

    def _reachability_index(self, target_eas: Set[int]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "_comment": ("Distilled entry->target reachability (provenance: static). Whole-program shortest path "
                         "from the entry point. keys = target function RVAs. shortest_path_rvas is ONE "
                         "representative path; n_paths = how many simple paths exist. reachable:false = orphan "
                         "(use r2_xrefs_to). r2 address = r2_baddr + rva."),
            "entry_rva": self.rva(self.ep) if self.ep is not None else None,
        }
        for ea in sorted(target_eas):
            r = self._reachability(ea)
            out[self.rva(ea)] = {
                "reachable": r["reachable"], "min_depth": r["min_depth"],
                "shortest_path_rvas": r["via_path_rvas"], "n_paths": r["n_paths"],
            }
        return out

    def _function_index(self, func_eas: Set[int], in_clusters: Dict[int, List[str]], prefixes: Dict[int, str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "_comment": ("Per-function projection (provenance: static except function_prefix = llm). Emitted ONLY "
                         "for in-scope functions (signal clusters / orphans), never the whole binary. `indirect` = "
                         "artifacts reachable via callees (whole-program propagation); a large indirect count marks "
                         "a behavior-gating hub/dispatcher worth reading first. r2 address = r2_baddr + rva."),
        }
        for ea in sorted(func_eas):
            row = {
                "category": self._category(ea), "origin": self._origin(ea),
                "has_default_name": self._has_default_name(ea), "is_simple_api_thunk": self._safe_thunk(ea),
                "in_clusters": in_clusters.get(ea, []),
                "direct": self._typed_counts(ea, self.DIRECT),
                "indirect": self._typed_counts(ea, self.INDIRECT),
            }
            pfx = prefixes.get(ea)
            if pfx:
                row["function_prefix"] = {"provenance": "llm", "text": pfx}
            out[self.rva(ea)] = row
        return out

    def _entities_catalog_full(self) -> List[Dict[str, Any]]:
        kinds = {1: "lib", 2: "api", 3: "string", 4: "capa", 5: "api_trace"}
        out = []
        for idx in range(len(self.entities)):
            try:
                ent = self.entities[idx]
                group, name, type_id = ent[0], ent[1], ent[2]
            except Exception:
                continue
            try:
                xc = len(self.x.entity_xrefs.get(idx, ()) or ())
            except Exception:
                xc = 0
            out.append({"idx": idx, "kind": kinds.get(int(type_id), str(type_id)),
                        "group": (str(group) if group is not None else None), "name": name, "xref_count": xc})
        return out

    def _report_md(self, has_llm: bool) -> Optional[str]:
        if not has_llm:
            return None
        report = self.ca.get("binary_report") if isinstance(self.ca, dict) else None
        if not report or str(report).strip() in ("", "No report available."):
            return None
        header = ("<!--\n  PROVENANCE: llm  |  REFERENCE ONLY\n"
                  "  xrefer's LLM-authored narrative (cluster_analysis.binary_report). A Tier-2 pointer target,\n"
                  "  never your report's spine — using its framing anchors you on xrefer's hypotheses (the\n"
                  "  'listing is not reverse engineering' failure). Treat every claim as a lead to verify by\n"
                  "  r2_decompile'ing the body, and cite the address/function behind each claim in your report.\n-->\n\n")
        return header + str(report)

    # ---- image / meta blocks ----
    def _sha256(self) -> Optional[str]:
        try:
            return self.x._backend.binary_hash
        except Exception:
            pass
        try:
            with open(self.x._backend.path, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()
        except Exception as e:
            log(f"[agent_map] sha256 unavailable: {e}")
            return None

    def _image_block(self) -> Dict[str, Any]:
        path = getattr(self.x._backend, "path", None)
        fmt = None
        try:
            fmt = self.x._backend.filetype()
        except Exception:
            pass
        bits = None
        for attr in ("is_64bit",):
            v = getattr(self.x.lang, attr, None) if getattr(self.x, "lang", None) else None
            if v is not None:
                bits = 64 if v else 32
        return {
            "sha256": self._sha256(),
            "filename": (os.path.basename(path) if path else None),
            "format": fmt,
            "bits": bits,
            "image_base_va": f"0x{self.ib:x}",
            "join_key": "rva",
            "entry_points_rva": [self.rva(self.ep)] if self.ep is not None else [],
            "recipe": ("r2_addr = r2_baddr + rva. For a normally-mapped image r2_baddr == image_base_va. "
                       "If your r2 session is rebased (PIE/ASLR/-B), substitute your own baddr and confirm "
                       "against one known function before trusting the rest."),
            "note": ("sha256 is the integration key: r2_init_project keys its project by the same sha256, so a "
                     "map is present iff it matches your sample. *_va fields are informational; *_rva fields are "
                     "the portable join key. REFUSE to apply RVAs/annotations on a sha256 mismatch."),
        }

    def _provenance_legend(self) -> Dict[str, Any]:
        return {
            "static": "Ground truth from disassembly, imports, xrefs, execution paths, and capa. Safe to state as fact.",
            "llm": ("A hypothesis from an LLM (cluster labels/descriptions/relationships, binary category/"
                    "description/report, all MITRE, and the cluster library_or_runtime verdict + per-function "
                    "origin it drives). Confirm by reading the body before citing or applying."),
            "values": ["static", "llm"],
            "rule": ("Filter to provenance=='static' for anything you state as fact. Every llm block names a "
                     "verify_against pointer -> the exact function(s) to r2_decompile to confirm it."),
            "correction": ("cluster is_library / library_kind=='llm' and per-function `origin` are LLM-DERIVED "
                           "(they inherit the LLM library_or_runtime verdict). The genuinely-STATIC library skip "
                           "signal is category=='func_lib' / is_simple_api_thunk / has_default_name — never skip "
                           "a function on origin. A danger_floor cluster is force-kept even if flagged library."),
        }

    def build_bundle(self) -> Dict[str, Any]:
        """Assemble the full tiered bundle as in-memory objects. Returns a dict
        the exporter serializes to files: {'map', 'clusters', 'indices',
        'entities', 'report_md', 'signal_order'}."""
        has_llm = bool(self.ca)
        records = self._classify()
        orphans = self._orphans_index()

        # Tier-1: one detail file per signal cluster.
        clusters_out: Dict[str, Dict[str, Any]] = {}
        signal_order: List[str] = []
        prefixes: Dict[int, str] = {}
        in_clusters: Dict[int, List[str]] = {}
        scope_funcs: Set[int] = set()
        for r in records:
            cl = r["cl"]
            for ea in cl.nodes:
                in_clusters.setdefault(ea, [])
                if r["root_rva"] not in in_clusters[ea]:
                    in_clusters[ea].append(r["root_rva"])
            if not r["signal"]:
                continue
            detail = self._cluster_detail(r, has_llm)
            clusters_out[r["root_rva"]] = detail
            signal_order.append(r["root_rva"])
            scope_funcs.update(cl.nodes)
            pfx = ((detail.get("llm") or {}).get("function_prefix")) if has_llm else None
            if pfx:
                for ea in cl.nodes:
                    prefixes.setdefault(ea, pfx)

        orphan_eas = set()
        for o in orphans:
            try:
                orphan_eas.add(int(o["func_rva"], 16) + self.ib)
            except Exception:
                pass
        scope_funcs |= orphan_eas
        # Reachability targets = signal cluster roots + orphan functions.
        target_eas = set(r["root_ea"] for r in records if r["signal"]) | orphan_eas

        queue = self._investigation_queue(records, orphans, has_llm)
        clusters_index = self._clusters_index(records, has_llm)

        indices = {
            "reverse_index.json": self._reverse_index(),
            "reachability.json": self._reachability_index(target_eas),
            "functions.json": self._function_index(scope_funcs, in_clusters, prefixes),
        }
        entities = self._entities_catalog_full()
        report_md = self._report_md(has_llm)

        try:
            from xrefer import __version__ as _ver
        except Exception:
            _ver = "unknown"

        clusters_signal = sum(1 for r in records if r["signal"])
        lib_funcs = sum(1 for ea in self.gx if self._category(ea) == "func_lib")
        functions_total = len(self.gx)
        stats = {
            "functions_total": functions_total,
            "user_functions": functions_total - lib_funcs,
            "library_functions": lib_funcs,
            "clusters_total": len(records),
            "clusters_signal": clusters_signal,
            "clusters_library": len(records) - clusters_signal,
            "clusters_excluded_from_tier1": len(records) - clusters_signal,
            "entities_total": len(self.entities),
            "orphan_count": len(orphans),
            "has_api_trace": any(int(self.entities[i][2]) == 5 for i in range(len(self.entities))),
            "backend_live": self._backend_live,
            "note": ("Library/noise clusters are flagged, excluded from the queue and Tier-1 dossiers, but still "
                     "listed in clusters_index and one fetch away. A 'library' cluster is recoverable if you "
                     "suspect mislabeling. backend_live=false means this was a headless load-from-cache export: "
                     "per-function has_default_name is null and category/origin come from persisted cluster "
                     "membership (static func_lib detection needs the live backend, i.e. the in-tool export)."),
        }

        top_roots = [r["root_rva"] for r in records if r["signal"]][:5]
        mp: Dict[str, Any] = {
            "schema": {
                "format": "xrefer-agent-map", "schema_version": SCHEMA_VERSION,
                "generator": f"xrefer {_ver}", "has_llm_layer": has_llm,
                "address_encoding": "hex-string RVA relative to image_base; see image.recipe",
                "workflow_binding": {
                    "target_skill": "format_binary (persistent radare2 project, sha256-keyed)",
                    "note": ("This map pre-computes format_binary Step 2 (triage) and Step 3 (indicator->code "
                             "pivots), delivering you into Step 4 (read the bodies). It does NOT satisfy the hard "
                             "gate: every llm value is a 'listing' hypothesis you must confirm by r2_decompile'ing "
                             "the body before you claim it or apply an annotation."),
                    "section_to_step": {
                        "investigation_queue": "Step 2/3: your ranked shortlist of functions that matter",
                        "indices/reverse_index.json": "Step 3: precomputed r2_xrefs_to (artifact -> functions)",
                        "indices/reachability.json": "Step 3: whole-program entry->function paths",
                        "clusters/<root_rva>.json static.artifacts.call_site_rvas": "Step 4: exact addresses to r2_decompile",
                        "clusters/<root_rva>.json llm.verify_against": "Step 4: the must-read functions to confirm the label",
                    },
                },
            },
            "image": self._image_block(),
            "entry_anchor": {
                "entry_points_rva": [self.rva(self.ep)] if self.ep is not None else [],
                "application_roots_rva": top_roots,
                "read_first_rva": ([queue[0]["ref"]] if queue else []),
                "runtime_note": ("Application logic lives in the signal clusters (application_roots_rva); clusters "
                                 "flagged is_library are runtime/library. For a Go or stripped sample, read the "
                                 "highest-scored signal roots first and treat library clusters as ignorable."),
            },
            "provenance_legend": self._provenance_legend(),
            "stats": stats,
            "binary": {
                "provenance": "llm",
                "category": self.ca.get("binary_category") if has_llm else None,
                "description": self.ca.get("binary_description") if has_llm else None,
                "report_ref": ("indices/report.md" if report_md else None),
                "report_present": bool(report_md),
                "verify": ("category/description are LLM verdicts. Confirm against the clusters and your own "
                           "r2_decompile output before repeating them."),
            },
            "investigation_queue": queue,
            "clusters_index": clusters_index,
            "mitre": self._mitre_killchain(has_llm),
            "orphans_index": orphans,
            "manifest": None,  # filled by the exporter once file sizes are known
        }
        return {"map": mp, "clusters": clusters_out, "indices": indices,
                "entities": entities, "report_md": report_md, "signal_order": signal_order}


def build_anatomy(xrefer: Any) -> Dict[str, Any]:
    """Return the anatomy dict for an analysed XRefer instance."""
    return _Builder(xrefer).build()


def export_anatomy(xrefer: Any, out_path: str) -> str:
    """Write the single-file anatomy JSON to ``out_path``; returns the path."""
    data = build_anatomy(xrefer)
    # Compact JSON so the single file stays chat-pasteable.
    _dump = lambda o: json.dumps(o, ensure_ascii=False, separators=(",", ":"))
    # fixed-point declared_bytes so the integrity trailer is exact
    data["_end"]["declared_bytes"] = 0
    raw = _dump(data)
    cur = len(raw.encode("utf-8"))
    n = cur
    for _ in range(6):
        n = cur - 1 + len(str(n))
    data["_end"]["declared_bytes"] = n
    raw = _dump(data)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    log(f"[agent_map] wrote {out_path} ({len(raw.encode('utf-8'))} bytes, "
        f"{len(data['clusters'])} signal clusters, has_llm={data['meta']['has_llm_layer']})")
    return out_path


def build_agent_map(xrefer: Any) -> Dict[str, Any]:
    """Return the in-memory tiered bundle for an analysed XRefer instance."""
    return _Builder(xrefer).build_bundle()


def export_agent_map(xrefer: Any, out_dir: str) -> str:
    """Write the tiered ``xrefer-agent-map`` bundle under ``out_dir``.

    Layout::

        <out_dir>/map.json                    Tier-0 (verdict, ranked queue, indexes)
        <out_dir>/clusters/<root_rva>.json     Tier-1 (one per signal cluster, full evidence)
        <out_dir>/indices/reverse_index.json   Tier-2 (artifact -> functions)
        <out_dir>/indices/reachability.json    Tier-2 (entry -> function shortest paths)
        <out_dir>/indices/functions.json       Tier-2 (per-function classification + counts)
        <out_dir>/indices/entities.json        Tier-2 (full artifact catalog)
        <out_dir>/indices/report.md            Tier-2 (LLM narrative; reference only)

    Tier-1/2 files are pretty-printed (lazy-loaded, human-readable, not
    chat-pasteable). ``map.json``'s manifest is finalized last, once the
    sizes of every other file are known. Returns the bundle directory.
    """
    bundle = build_agent_map(xrefer)
    clusters_dir = os.path.join(out_dir, "clusters")
    indices_dir = os.path.join(out_dir, "indices")
    os.makedirs(clusters_dir, exist_ok=True)
    os.makedirs(indices_dir, exist_ok=True)

    def _write(path: str, obj: Any) -> int:
        raw = json.dumps(obj, ensure_ascii=False, indent=2)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raw)
        return len(raw.encode("utf-8"))

    # Tier-1: cluster dossiers (emitted in queue/score order).
    tier1_files: List[Dict[str, Any]] = []
    for root_rva in bundle["signal_order"]:
        rel = f"clusters/{root_rva}.json"
        nbytes = _write(os.path.join(out_dir, rel), bundle["clusters"][root_rva])
        tier1_files.append({"path": rel, "root_rva": root_rva, "bytes": nbytes})

    # Tier-2: indices + entities + report.
    tier2: List[Dict[str, Any]] = []
    _load_when = {
        "reverse_index.json": "you need every function that references an artifact/IOC (precomputed r2_xrefs_to)",
        "reachability.json": "you need how execution reaches a function from entry (whole-program, not an r2 call)",
        "functions.json": "you need classification or DIRECT/INDIRECT artifact counts for an in-scope function",
    }
    for fname, obj in bundle["indices"].items():
        rel = f"indices/{fname}"
        nbytes = _write(os.path.join(out_dir, rel), obj)
        tier2.append({"path": rel, "bytes": nbytes, "load_when": _load_when.get(fname, "")})
    rel = "indices/entities.json"
    nbytes = _write(os.path.join(out_dir, rel), bundle["entities"])
    tier2.append({"path": rel, "bytes": nbytes,
                  "load_when": "you need the full artifact catalog / to resolve an entity_idx to a name"})
    if bundle["report_md"] is not None:
        rel = "indices/report.md"
        raw = bundle["report_md"]
        with open(os.path.join(out_dir, rel), "w", encoding="utf-8") as fh:
            fh.write(raw)
        tier2.append({"path": rel, "bytes": len(raw.encode("utf-8")),
                      "load_when": "you want xrefer's LLM narrative (reference only — do NOT use as your report's spine)"})

    # Finalize the manifest and write Tier-0 map.json.
    bundle["map"]["manifest"] = {
        "tier1_dir": "clusters/",
        "tier1_files": tier1_files,
        "tier2": tier2,
        "read_order": ["map.json", "top investigation_queue items -> their detail_ref -> Step 4 r2_decompile",
                       "indices/* only to run a specific pivot"],
    }
    map_path = os.path.join(out_dir, "map.json")
    map_bytes = _write(map_path, bundle["map"])

    total = map_bytes + sum(f["bytes"] for f in tier1_files) + sum(f["bytes"] for f in tier2)
    log(f"[agent_map] wrote tiered bundle to {out_dir}/ "
        f"({len(tier1_files)} signal clusters, {len(tier2)} index files, {total} bytes total, "
        f"has_llm={bundle['map']['schema']['has_llm_layer']})")
    return out_dir
