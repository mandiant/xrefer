---
name: xrefer_binary_anatomy
description: >-
  Augments the format_binary (radare2) workflow. When an xrefer-agent-map bundle exists for the
  sample's sha256 (a map.json plus clusters/ and indices/ directories), it pre-computes your triage
  sweep and indicator->code pivots and drops you into the read-the-bodies step with a ranked queue of
  the functions that matter and the exact addresses to decompile. Load map.json at r2_init_project
  time. It is reconnaissance, not analysis: you still read (decompile, or disassemble on failure) every
  body before you claim it.
---

# xrefer_binary_anatomy — the tiered xrefer-agent-map bundle (a format_binary accelerator)

## 0. Prerequisite

Confirm the **`malware_analysis`** and **`format_binary`** skills are active in this session, and
**activate them if they are not.** This skill only augments them: `malware_analysis` owns the report
format and RE doctrine, `format_binary` drives radare2, this map pre-computes their triage. Say so if
they are unavailable.

## 1. What it is

xrefer already ran whole-program analysis and produced a **curated, de-noised, semantically-grouped**
version of the triage and pivots you would do by hand: clustered imports/strings/capa, a precomputed
`r2_xrefs_to`, whole-program reachability, and an LLM interpretation layer. It tells you **where to point
`r2_decompile`**, not what the code does. It is **lazy-loaded** — load `map.json` at `r2_init_project`
time, then fetch other files only when a pivot needs them. **`manifest` is the file index**: it lists
every `clusters/*.json` and index, and `manifest.tier2[].load_when` says when to open each — consult it
instead of loading everything.

## 2. Bind + provenance (fail-closed)

- **Bind:** `r2_addr = r2_baddr + rva` (see `image.recipe`). **If `image.sha256` != your
  `r2_init_project` sha256, REFUSE** — different sample; do not apply these RVAs or any rename.
- **Provenance (`provenance_legend`):** state as fact only `"provenance":"static"` values (RVAs, artifact
  names, xrefs, paths, capa, classification, each cluster's `static.artifacts.libs`). Everything
  `"provenance":"llm"` — cluster `label`/`function_prefix`/`mitre`, the `binary` verdict — is a
  **hypothesis** that satisfies your gate for nothing. Its `correction`: cluster `is_library` /
  `library_kind=="llm"` and per-function `origin` are LLM-derived, **not** skip authority; the static
  skip signal is `category=="func_lib"`.
- **Cluster identity is `root_rva`** (also the address to decompile). The `cluster.id.NNNN` tokens in a
  cluster's `llm.relationships` are run-local — never keys; each is pre-resolved in
  `llm.resolved_relationships`.

## 3. THE CORE LOOP — work the queue, decompile recursively, disassemble on failure

`investigation_queue` is xrefer's ranked shortlist. **`score` is the ORDER you work in, not a license to
skip** — take every item to a resolution (confirmed / dismissed-with-evidence / blocked) before you
write. For each item (its `detail_ref` names the Tier-1 file, open `clusters/<root_rva>.json`):

1. **Decompile the root AND every `must_read_rvas`** (= `llm.verify_against.key_function_rvas`, the
   artifact-bearing members), jumping to `static.artifacts.*.call_site_rvas`. **The root alone is never a
   disposition** — it is usually a dispatcher.
2. **Recurse down the call chain.** `static.edges` is the cluster's real call graph and
   `static.subcluster_refs[].child_root_rva` are trustworthy links into child clusters — **decompile the
   callees too**, stepping into any child that consumes data you care about, until a leaf body proves the
   behavior. `r2_callees` for anything beyond the dossier's edges.
3. **On decompile failure, disassemble.** When `r2_decompile` errors or returns garbage (r2ghidra can
   choke on obfuscated/odd code), fall back to **`r2_disasm`** for that function; use `r2_get_bytes` /
   `r2_get_string` for data. **Never leave a must-read uncovered because the decompiler failed** — mark it
   blocked only if both fail.
4. **Skip a function only on the STATIC** `category=="func_lib"` / `is_simple_api_thunk` (prioritize
   `origin:"user"`), never on LLM library framing.

**The gate:** no capability claim without a body you read; no confirmed function left unnamed; rename only
on evidence. `llm.mitre[].rationale` is the exact claim to confirm; `llm.unresolved_run_ids` is an honest
gap — do not invent that edge.

**Crypto note (anti-tunnel-vision):** each dossier's `static.artifacts.libs` lists the crates its
functions link. Report **every** cipher crate you see, not just the loudest — a ransomware build routinely
links several (`chacha20` + `aes` + `ctr` for the encryptor, `rsa` for key wrapping). Primary vs secondary
comes from the bodies, not frequency; a linked crypto crate is evidence even with a null `danger_floor`.

## 4. Cookbook — when you need X, open Y (lazy-load only these)

| you need… | open |
|---|---|
| the ranked functions that matter | `map.json` → `investigation_queue` (+ each `detail_ref`) |
| which functions reference an API/IOC (precomputed `r2_xrefs_to`) | `indices/reverse_index.json["<entity_idx>"].function_rvas` (scoped to in-scope artifacts; `r2_xrefs_to` for others) |
| how entry reaches function Y | `indices/reachability.json["<Y>"]` → `shortest_path_rvas` / `n_paths` |
| the dispatcher / config-gating hub | highest `indices/functions.json[fn].indirect` in scope |
| an artifact-bearing function with no path from entry | `orphans_index[]` → `r2_xrefs_to` it (its `next`) |
| an `entity_idx` → name / kind / xref_count | `indices/entities.json` |
| the crates a cluster links, and where | `clusters/<root_rva>.json` → `static.artifacts.libs` |
| the MITRE kill-chain + what grounds each technique | `map.json.mitre` → `tactics_kill_chain_order`, `groundings[].cluster_root_rva` |
| what was DEMOTED (library/orphan), i.e. what you skipped | `clusters_index` (`is_library` / `detail_ref:null`) + `stats.clusters_library` |

`indices/report.md` is xrefer's LLM narrative — **reference only, never your report's spine.**

## 5. What you may skip, and completeness

- **The demoted set is the only budget lever.** `clusters_index` lists **every** cluster; a row with
  `is_library:true` + `detail_ref:null` was excluded from the queue and Tier-1. `library_kind=="static"`
  (deterministic FUNC_LIB) is safe to leave unread; `library_kind=="llm"` you MAY leave unread to save
  budget, but it is visible, not triaged. **Never** skip an `investigation_queue` item.
- Any cluster with `danger_floor` set or `promoted_from_noise:true` reaches the danger set statically and
  is force-kept in the queue even if the LLM called it library — a mislabeled payload cannot hide. Do not
  conclude "clean" from a short queue; the safety net is static, and `stats.clusters_library` is what you
  chose not to open.

## 6. The deliverable — a malware analysis report (NOT a verification log)

Produce a **standard malware analysis report in your `malware_analysis` format**, self-contained in these
sections: **executive summary → identification (`image`) → capabilities (organized by behavior, not
cluster) → details (a full technical walkthrough of the entire malware, component by component) →
host-based indicators → network-based indicators → MITRE ATT&CK → conclusion.** **Do NOT open with a
disposition ledger or coverage header** — the map governs what you may claim, not your report shape;
verification lives *inline*.
- Every capability and IOC carries, inline, the **member** RVA (at its call site) whose body proves it.
- State an xrefer hypothesis only after confirming it in a body; build from **behaviors you confirmed**,
  NOT from `indices/report.md`.
- Report every crypto crate from the clusters' `static.artifacts.libs`.
- Map MITRE technique-ids to confirmed behavior via `tactics_kill_chain_order` (`empty_tactics` =
  unmapped, NOT proof of absence — a static `danger_floor` overrides it). Pivot IOCs via
  `get_context_for_hash` / `get_ioc_assessment`.
- **Coverage is internal discipline, not a section:** cover every queue item and don't claim
  complete/benign while a `danger_floor` cluster is unread — but that governs your analysis, it is not printed.

## 7. Degraded mode & backend_live

- **`schema.has_llm_layer:false`** → `binary`, `mitre`, every `llm` block and `clusters_index`/queue
  labels are null; the queue is scored on static signals only. The static skeleton (clusters, edges,
  artifacts + call sites, reachability, reverse index, orphans, danger_floor) is still a complete
  accelerator — work the queue and derive the verdict yourself.
- **`stats.backend_live:false`** → exported headless from cache; `has_default_name` is null and
  `category`/`origin` come from persisted membership. Trust them as membership-derived; treat
  `has_default_name:null` as "unknown," not "false."

## Not in this bundle (do not look for them)

The bundle omits fields with no non-fabricated static source: per-cluster `recipe`/`pattern`, crypto
`carve_targets`, staged `suggested_annotations`, `all_paths_ref` sidecars. Confirm crypto by decompiling
the routine and carving its data refs; recover extra paths with `r2_callees`. `indices/entities.json`
carries only static facts (no LLM category/enrichment). Do not ask the map for a full callgraph or
all-paths you can get from r2, and do not treat it as exhaustive — the demoted set still exists.
