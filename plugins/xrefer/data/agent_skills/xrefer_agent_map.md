---
name: xrefer-agent-map
description: >-
  Augments the format_binary (radare2) workflow. When an xrefer-agent-map bundle exists for the
  sample's sha256 (a map.json plus clusters/ and indices/ directories), it pre-computes your Step-2
  triage sweep and Step-3 indicator->code pivots and drops you into Step 4 with a ranked list of the
  functions that matter and the exact addresses to r2_decompile. Load map.json at r2_init_project
  time. It is reconnaissance, not analysis: it never satisfies your hard gate — you still read every
  body before you claim it.
---

# xrefer-agent-map (a format_binary accelerator)

## 0. Prerequisite — activate your analysis skills first

Before anything below, **confirm the `malware_analysis` and `format_binary` skills are active** in this
session, and **activate them if they are not.** This skill only augments that workflow: `malware_analysis`
owns the report format and reverse-engineering doctrine, `format_binary` drives radare2, and this map
pre-computes their triage and pivots. If those skills are unavailable, say so before proceeding.

## 1. What it is and where it fits

This is **not** a replacement for `format_binary` — it plugs into it. xrefer already ran whole-program
analysis on this sample and produced a **curated, de-noised, semantically-grouped** version of the
triage and pivots you would do by hand: clustered imports/strings/capa, a precomputed `r2_xrefs_to`,
whole-program reachability, and an LLM interpretation layer. Its job is to spend your r2 budget where
it matters — it tells you **where to point `r2_decompile`**, not what the code does. The tiered layout
is for binaries too large for the single-file `binary_anatomy`: everything is split across files and
**lazy-loaded** — fetch only what a given pivot needs.

**Load `map.json` at `r2_init_project` time** if a bundle exists for this sha256. Then run the normal
6 steps — `schema.workflow_binding.section_to_step` maps each section to the step it accelerates.

## 2. THE HARD GATE STILL APPLIES (read this twice)

Everything with `"provenance":"llm"` — cluster `label`, `function_prefix`, `mitre`, the `binary`
verdict — is a **"listing": a hypothesis that satisfies your gate for nothing.** Your
rule is unchanged: *no capability claim without a function body read; no confirmed function left
unnamed; rename only on evidence.* The map's value is that it names **exactly which body** proves each
hypothesis (each queue item's `must_read_rvas`, = `llm.verify_against.key_function_rvas`, at their
`static.artifacts.*.call_site_rvas`). A report assembled from this map alone is the "listing is not
reverse engineering" failure. Facts you may state
directly are only the `"provenance":"static"` ones (RVAs, artifact names, xrefs, paths, capa,
classification, and `dependency_bom` — the linked-crate parts list). See `provenance_legend` — and its
`correction`: cluster `is_library` / `library_kind=="llm"` and per-function `origin` are LLM-DERIVED,
not skip authority.

## 3. Addressing, keys, and binding

- `r2_addr = r2_baddr + rva` (see `image.recipe`). For a normally-mapped image `r2_baddr ==
  image.image_base_va`; if your session is rebased (PIE/ASLR/-B) substitute your own baddr and confirm
  one known function first.
- The bundle matches this sample **iff `image.sha256` == your `r2_init_project` sha256.** If it does
  not, do not apply these RVAs or any rename — it is a different sample.
- **Cluster identity is `root_rva`** (also the address to `r2_decompile`). The `cluster.id.NNNN` tokens
  that appear inside a cluster's `llm.relationships` are run-local — never use them as keys; each is
  pre-resolved to a `root_rva` for you in that cluster's `llm.resolved_relationships`.

## 4. Step-by-step: how the map folds into format_binary

**Step 1 (init)** — after `r2_init_project`, load `map.json`. Read `entry_anchor` (application vs
runtime roots; `read_first_rva`), `stats`, the `binary` verdict (a hypothesis), and the `mitre`
kill-chain. Check `stats.backend_live` (see §7).

**Step 2 (triage) — mostly done for you.** Use `investigation_queue` instead of a blind sweep, and
`indices/entities.json` (curated, de-noised) instead of raw `r2_imports`/`r2_find_regex`. This is the
fix for the Go / statically-linked **blind-regex failure**: xrefer already separated signal from the
tens-of-thousands-of-strings noise. Spot-check with `r2_find_regex` only if the map looks thin.

Read **`dependency_bom`** here first — it is the static crate/library parts list (from linked symbols),
`signal` = cluster-local deps (crypto/compression/parsers/the sample's own modules, each with an
`entity_idxs` and a `clusters_rva` → the cluster(s) that use it) and `pervasive` = language/runtime
crates. **Crypto-claim discipline (where the "it only uses RC4" tunnel-vision fails):** report EVERY
cipher/crypto crate in `signal`, not just the loudest — a ransomware build routinely links several
(e.g. `chacha20` + `aes` + `ctr`/`cipher` for the file encryptor and `rsa` for key wrapping). Follow
each crate's `clusters_rva` to its dossier, read the `must_read_rvas` bodies, and decide primary
(encrypts victim data) vs secondary (key wrap / hashing / string obfuscation) from **behavior, not
xref count** — a low-xref crate can be the primary bulk encryptor. A statically-linked crypto crate has
no CryptoAPI import, so its cluster can rank mid-queue and its `danger_floor` can be null; that is not
license to skip it. If `dependency_bom.signal` names a cipher, the binary HAS it — confirm *how* it is
used, never *whether* it is present.

**Step 3 (pivot) — precomputed.** `indices/reverse_index.json["<entity_idx>"].function_rvas` is your
`r2_xrefs_to` result (artifact → referencing functions). A large `indices/functions.json[fn].indirect`
count is xrefer naming the dispatcher/hub you would otherwise hunt with `r2_callees`.
`indices/reachability.json["<rva>"]` gives `reachable` / `min_depth` / `shortest_path_rvas` / `n_paths`
(a whole-program path from entry — not a single r2 call).

**Step 4 (read the bodies) — THIS IS STILL YOUR JOB.** Walk `investigation_queue` top-down. **`score`
sets the ORDER you work in, not a skip license — investigate every queue item to a resolution
(confirmed / dismissed-with-evidence / blocked) before you write.** This is internal coverage, not a
report section (Step 6); the queue is xrefer's triaged shortlist, so a dropped item is signal you chose
not to look at. Each item's `must_read_rvas` is the bounded depth floor and `detail_ref` names its
Tier-1 file. For each item open `clusters/<root_rva>.json`:
- `r2_decompile` the root **and every `must_read_rvas` function** (= `llm.verify_against.key_function_
  rvas` — the artifact-bearing members), jumping to `static.artifacts.*.call_site_rvas`. **The root
  alone is not a disposition** — it is often just a dispatcher; the body that *makes* the call is
  usually a member. Skip a function only on the STATIC `category=="func_lib"` / `is_simple_api_thunk`
  (prioritize `origin:"user"`), never on the LLM library framing.
- **Follow the behavior down the call chain.** `static.edges` is the cluster's real call graph and
  `static.subcluster_refs` (`child_root_rva`) are trustworthy linkages into child clusters — step into
  any child that consumes a parameter you care about.
- `llm.mitre[].rationale` is the exact claim to confirm. `llm.resolved_relationships` pre-resolves the
  cluster's prose `cluster.id.NNNN` references to root RVAs; `llm.unresolved_run_ids` is an honest gap
  — do not invent that edge.

**Step 5 (annotate) — on evidence.** After you confirm a function, name it what the body does with
`r2_rename` and `r2_set_comments` (xrefer supplies `llm.function_prefix` as a *suggested* prefix only —
a hypothesis, not a name to apply blind). Never apply a name you have not earned by reading the body.
`r2_save_project` at the end of a block.

**Step 6 (report) — a malware analysis report, NOT a verification log.** Produce a **standard malware
analysis report in your `malware_analysis` format**, self-contained in these sections: **executive
summary** (what the sample is, purpose, severity) → **identification** (sha256/filename/size/format/arch
+ language/packer, from `image`) → **capabilities** → **details** → **host-based indicators**
(files/registry/mutexes/services/processes) → **network-based indicators** (C2/URLs/protocols/ports) →
**MITRE ATT&CK** → **conclusion** (assessment + likely family/attribution + confidence). **Do NOT open
with a disposition ledger or a coverage header** — the map governs what you may claim, not your report
shape. Verification lives *inline*:
- Organize **capabilities by behavior** (execution, persistence, privilege-escalation, defense-evasion,
  credential-access, discovery, collection, cryptography, C2, exfiltration, impact) — **not cluster by
  cluster.** Synthesize; do not echo the map.
- The **details** section is a comprehensive technical walkthrough of the **entire** malware — its
  execution flow from entry through every major component, covering the full binary (not only the
  headline behaviors), each with its function RVAs and decompiled evidence. Capabilities is the summary;
  details is the in-depth analysis.
- Every capability and IOC carries, inline, the **member** RVA (at its call site) whose decompiled body
  proves it — never the cluster root alone, never a bare claim.
- State an xrefer hypothesis only after confirming it in a body; omit or mark "unconfirmed" the rest.
  Build from **behaviors you confirmed**, NOT from `indices/report.md` (LLM narrative, reference only).
- **Report every crypto crate** from `dependency_bom` — name each cipher and say which is primary vs
  secondary from the bodies.
- Map MITRE technique-ids to confirmed behavior via the kill-chain (`tactics_kill_chain_order`; each
  technique's `groundings[].cluster_root_rva` + `rationale` is the cluster + claim to test; `empty_
  tactics` = unmapped, NOT proof of absence — a static `danger_floor` overrides it). Pivot IOCs through
  `get_context_for_hash` / `get_ioc_assessment`.
- **Coverage is internal discipline, not a section:** don't claim complete/benign while a `danger_floor`
  cluster is unread (`stats.clusters_library` is what you demoted) — but that governs your analysis, it
  is not printed.

## 5. Query cookbook (map field → next r2 call)

- *Which functions reference this API/IOC?* → `reverse_index["<entity_idx>"].function_rvas` →
  `r2_decompile` each.
- *How does entry reach function Y?* → `reachability["<Y>"].shortest_path_rvas` (with `n_paths`).
- *Where is the dispatcher / config-gating hub?* → highest `functions.json[fn].indirect` in scope.
- *What does function W touch, and exactly where?* → its cluster's `static.artifacts.*.call_site_rvas`.
- *An artifact-bearing function with no path from entry?* → `orphans_index[]`; `r2_xrefs_to` it (the
  item's `next` field) to find the caller r2's static pass missed.
- *Resolve an entity_idx to a name/group/xref count?* → `indices/entities.json`.
- *What crypto / third-party crates does the binary link, and where?* → `map.json.dependency_bom.signal`
  → each crate's `clusters_rva` → open that dossier and read its `must_read_rvas`.

## 6. Noise, library demotion, completeness

Do not conclude "clean" just because the queue is short — the safety net is **static**. And note:
**budget-saving means leaving demoted `clusters_index` rows unread — never an `investigation_queue`
item** (investigate every queue item; Step 4).
- `clusters_index` lists **every** cluster (signal + demoted). A row with `is_library:true` and
  `detail_ref:null` was excluded from the queue and Tier-1. `library_kind` distinguishes `"static"`
  (deterministic FUNC_LIB — safe to leave unread) from `"llm"` (the `library_or_runtime` guess — the
  **budget lever**: leave unread to save budget, but it is visible, not triaged).
- Any cluster with `danger_floor` set (process-injection / crypto / net-exfil / cred-access imports) or
  `promoted_from_noise:true` reaches the danger set statically and is force-kept in the queue even if
  the LLM called it library — so a mislabeled payload cannot hide. Never skip on the LLM library flag
  when a static `danger_floor` disagrees.
- `stats.clusters_library` tells you how many clusters were demoted (excluded from the queue and
  Tier-1); a mislabeled cluster is recoverable — re-examine one if you suspect it.

## 7. Degraded mode and backend_live

- **`schema.has_llm_layer:false`** → `binary`, `mitre`, every cluster `llm` block, and the labels in
  `clusters_index`/`investigation_queue` are null, and the queue is scored on static signals only.
  The static skeleton (clusters, edges, artifacts+call sites, reachability, reverse index, orphans,
  danger_floor) is still a complete Step-2/3 accelerator — proceed on structure, derive the verdict
  yourself. No `"provenance":"llm"` value exists in the bundle, so nothing needs de-hypothesizing —
  you still read the bodies as always.
- **`stats.backend_live:false`** → this bundle was exported headless from a cached analysis where the
  live disassembler backend was unavailable, so per-function `has_default_name` is `null` and
  `category`/`origin` come from persisted cluster membership (static `func_lib` detection needs the
  live backend, i.e. the in-tool export). Trust `category`/`origin` as membership-derived; treat
  `has_default_name:null` as "unknown," not "false."

## 8. Anti-patterns

Do NOT: report a capability you only saw in the map (no body read); apply a `function_prefix` before
verifying; treat `label`/`mitre`/the `binary` verdict as fact; use absolute VAs or run-local
`cluster.id.NNNN` tokens as stable keys; ask the map for a full callgraph or all-paths you can get from
r2; or treat the map as exhaustive (library/orphan functions it demotes still exist —
`stats.clusters_library` names what was skipped).

## Fields NOT in this bundle (do not look for them)

The shipped bundle deliberately omits fields that have no non-fabricated static source: per-cluster
`recipe`/`pattern` strings, crypto `carve_targets`, staged `suggested_annotations`, and `all_paths_ref`
sidecars. Confirm crypto by decompiling the routine and carving its data references yourself; recover
extra paths with `r2_callees`. `indices/entities.json` carries only static facts — `idx`/`kind`/`name`/
`xref_count` (plus a static capa `namespace` on capa entities); no LLM category/enrichment.
