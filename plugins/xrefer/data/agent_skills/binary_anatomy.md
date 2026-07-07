---
name: binary_anatomy
description: >-
  Consume an xrefer "binary anatomy" — a single, chat-pasteable JSON map of a native binary
  (recognizable by _readme.format == "xrefer-binary-anatomy" and the _end.sentinel
  "XREFER_ANATOMY_EOF"). Use it as a pre-computed investigation PLAN that ranks where to point
  radare2 first and carries xrefer's interpretations as null-verdict hypotheses. Activate when
  format_binary has an anatomy JSON for the sample's sha256. It never replaces reading bodies:
  every capability claim still requires an r2_decompile. Leans on the format_binary radare2
  toolset for all verification.
---

# binary_anatomy — consuming a single-file xrefer map

## Prerequisite — activate your analysis skills first

Before anything below, **confirm the `malware_analysis` and `format_binary` skills are active** in this
session, and **activate them if they are not.** This skill only augments that workflow: `malware_analysis`
owns the report format and the reverse-engineering doctrine, `format_binary` drives radare2, and this map
pre-computes their triage and pivots. If those skills are unavailable, say so before proceeding.

## What this is (and is not)

An `xrefer-binary-anatomy` JSON is a **plan**, not an analysis. It is xrefer's ranked answer to
"where do I point radare2 first, and what do I expect to find" — plus a **hypothesis layer** you must
burn down against r2. It carries **no decompiled code** by design, so the only material a real
capability claim can be built from is r2 output that does not exist until you make the call. Building
a report by quoting this paste is the "listing is not reverse engineering" failure your
`format_binary` doctrine forbids. It fast-forwards Steps 2–3 (triage + indicator→code pivots) and
drops you into Step 4 (read the bodies).

## 0. INGEST — is the paste even intact?

The JSON may arrive as chat text and can be silently clipped by a length limit. **Before parsing:**
- Confirm the raw text ends with the `_end` block `"sentinel": "XREFER_ANATOMY_EOF"`. If it does not,
  the paste was truncated in transit — **do not analyze a fragment; ask for a re-paste** (or the
  tiered `xrefer-agent-map` bundle for a large binary). A mid-array clip is invalid JSON anyway.
- `_end.declared_bytes` is the intended UTF-8 byte length; a large mismatch with what you received is
  another truncation signal.
- Read `_readme.counts` (`clusters_shown` / `clusters_total` / `clusters_static_lib` /
  `clusters_llm_lib`) so you know how much of the binary this file actually covers. When
  `clusters_shown < clusters_total`, `coverage.omitted` is authoritative about what was left out.

## 1. BIND — is this anatomy actually for the sample r2 loaded? (fail-closed)

`bind_check` is a hard precondition, not a courtesy:
- `r2_init_project` the sample; read r2's **real** baddr — do NOT assume it equals
  `bind_check.image_base` (`baddr_is_assumed` is true; ASLR/PIE/.NET break that).
- For every RVA in this file, `r2_addr = r2_baddr + rva` (see `bind_check.recipe`).
- **Verify sha256 first:** if `bind_check.sha256` != your sample's sha256, **REFUSE** — wrong sample.
- If `bind_check.expected_bytes_hex` is present, probe it: `r2_get_bytes` at
  `r2_baddr + bind_check.check_anchor_rva` and compare. On mismatch, follow `bind_check.on_mismatch`
  — **REFUSE**: do not `r2_decompile` against these RVAs and **never `r2_rename`** (a wrong-sample
  rename is a destructive write). (`expected_bytes_hex` may be null in headless exports; the sha256
  check is still binding.)

## 2. The two-world rule (provenance)

Read `_readme.provenance`. Two kinds of value live in this file:
- **Bare values = STATIC ground truth.** RVAs, imports/strings/capa names, `call_site_rvas`,
  `reachability.via_path_rvas`, `entities[]`, `danger_floor`, `noise.static_lib_*`,
  `coverage.omitted.notable_rvas`, `dependency_bom` (the crate parts list) and each function's
  `artifacts.libs` (cluster-local crate refs), and the static per-function skip signals
  `category=="func_lib"` / `is_simple_api_thunk`. You may state these as fact — a linked crate name
  is a symbol-table fact, not a guess.
- **Any object shaped `{"v": ..., "src": "xrefer_llm_guess"}` = a HYPOTHESIS.** Every LLM value is
  wrapped this way (the `verdict` block, each cluster's `llm` block, `llm_lib`). The `src` tag travels
  with the value even if you lift a sub-object in isolation, so a quoted `"keylogger"` still shows it
  is a guess. It confirms nothing until you read the body.
- **NOT static, despite looking plain:** cluster `llm_lib` and (in the cluster `llm` block) any
  library framing inherit the LLM `library_or_runtime` verdict. Never treat them as skip authority.

## 2b. The dependency BOM — the static crate parts list (crypto discipline)

`dependency_bom` is a **static** inventory of the crates/libraries the binary is built from, taken from
linked symbols — the most authoritative evidence of what primitives are actually present. Two lists:
- **`signal`** = cluster-local crates (crypto, compression, parsers, the sample's own modules), ranked
  most-specific first. Each row has `xrefs`, `n_clusters`, and `clusters_rva` → the exact cluster(s)
  that use it, so a crate name pivots straight to code to read.
- **`pervasive`** = crates spread across most clusters (language runtime / the sample's ubiquitous
  core), listed for completeness. The split is by reference **spread**, never by a hard-coded name
  list, so a novel or renamed crypto crate lands in `signal` like any other.

**Crypto-claim discipline — this list is where the "it uses RC4" tunnel-vision failure is caught:**
- **Report EVERY cipher/crypto crate in `signal`, not just the first or loudest one.** A ransomware
  build routinely links several (e.g. `chacha20` + `aes` + `ctr`/`cipher` for the file encryptor and
  `rsa` for key wrapping). Enumerate them all before you characterize the scheme.
- **Distinguish primary vs secondary by evidence, not by xref count.** Follow each crate's
  `clusters_rva` to the cluster, read the `must_read_rvas` bodies, and decide from behavior which cipher
  encrypts victim data (primary) vs. wraps keys / hashes / obfuscates strings (secondary). A crate with
  few xrefs can still be the primary bulk encryptor.
- **A statically-linked crypto crate is EVIDENCE, not noise.** It has no CryptoAPI import to trip
  `danger_floor`, so its cluster may rank mid-queue — do not let the ranking talk you out of it. If
  `dependency_bom.signal` shows a cipher, the binary has that cipher; your job is to confirm *how* it is
  used, never *whether* it is present.
- Per-function `artifacts.libs` carries the same crate refs at the call sites inside each cluster —
  use them to confirm the crate is invoked in the body you are reading, not merely linked.

## 3. The capability gate — ALWAYS applies (`_readme.capability_gate_applies` is always true)

**No capability sentence in your report without a decompiled body behind it — and that body is
usually a cluster *member*, not the root.** Every queue item carries `must_read_rvas` (the same set as
the cluster's `llm.verify_against.key_function_rvas`): the artifact-bearing functions that actually
make the API calls / hold the strings. **A cluster is NOT dispositioned until you `r2_decompile` every
one of its `must_read_rvas` at its `call_site_rvas`.** Decompiling only `ref_rva` (the root) is an
incomplete triage — the root is frequently just a dispatcher, and the behavior lives one or more hops
down. Only after reading the member bodies may you repeat the cluster's `label`/`description`/`mitre`.
This holds in degraded mode too: with `meta.has_llm_layer == false` there are no hypotheses to confirm,
but `investigation_queue[].why` and the static evidence are still only LEADS (where to point r2).

## 4. The loop — process EVERY queue item; score is order, not a skip license

Walk `investigation_queue` top to bottom. **`static_score` sets the ORDER you work in; it does NOT
license skipping.** Investigate every queue item to a resolution (confirmed / dismissed-with-evidence /
blocked) before you write — this is internal coverage discipline, **not** a section you print (§6). The
queue is already xrefer's triaged shortlist, so an item you drop is signal you chose not to look at. For
each item:
- Open `clusters[]` (match `root_rva == ref_rva`). `r2_decompile` the root **and every
  `must_read_rvas` function**, jumping to each function's `artifacts.*.call_site_rvas` (the exact
  instructions). `first_move` is the ready call.
- **Follow the behavior down the call chain — do not stop at the root.** The single file drops the
  cluster `edges` for size and caps its member list (`static.functions_omitted > 0` says how many were
  dropped), so recover the rest with `r2_callees` from the root and step into any child that consumes a
  parameter you care about. Trace how the root passes data to the leaf API calls; the body that *makes*
  the call is what proves the capability, and it is frequently a child.
- Skip a *function inside a cluster* only on the STATIC signals `category=="func_lib"` /
  `is_simple_api_thunk`. Never skip on LLM library framing — it can hide a mislabeled payload.
- `indirect_artifact_count` marks a behavior-gating hub — read it first. `reachability.via_path_rvas`
  shows how entry reaches the root (its second-to-last node is the caller = the trigger).
  `static.subcluster_refs[].at_node_rva`→`child_cluster_id` are real call linkages.
- Use `llm.mitre[].rationale` as the exact claim to confirm in the body.

## 5. Anti-hiding — the budget lever is the noise ledger, NOT the queue

**Budget-saving means skipping the demoted `noise` ledger below — never an `investigation_queue`
item.** The queue is the must-do set (§4). The `noise` block is what you are allowed to leave unread,
and even that has a static safety net:
- `noise.static_lib_count` / `static_lib_sample_rvas` (every member hit the static FUNC_LIB/thunk path)
  is deterministic library code, collapsed to a count — safe to skip.
- `noise.llm_lib_demoted` (LLM `library_or_runtime` guess, `{v,src}`-tagged, NOT statically confirmed)
  is the actual budget lever: you **MAY leave these unread to save decompiler budget** — that is their
  purpose — **but they are visible, not triaged.** Open one if a lead points into it or it appears in
  `coverage.omitted.notable_rvas`.
- `coverage.omitted.notable_rvas` lists, by RVA, every omitted cluster that **statically** reaches a
  danger floor (process-injection / crypto / net-exfil / cred-access imports). You **must r2-triage
  every one** before any completeness or "benign" verdict (see `coverage.omitted.note`).
- `noise.promoted_out`, and any item with `promoted_from_noise:true`, are clusters the LLM called
  "library" but that statically reach the danger set — already force-kept in the queue, so a
  mislabeled payload cannot hide. Never skip on the LLM library flag when a static `danger_floor`
  disagrees.

## 6. THE DELIVERABLE — a malware analysis report (NOT a verification log)

Follow `report_scaffold`. The output is a **standard malware analysis report in your `malware_analysis`
format** — an intelligence product, not a table of what you verified. This map governs only *what you
may claim and the evidence behind each claim*; it does **not** replace your report format. **Do not emit
a disposition ledger or a coverage header** — verification is expressed *inside* the report as the
evidence attached to each finding. Sections (`report_scaffold.sections`):
1. **Executive summary** — what the sample is, its purpose, and severity, in a few sentences.
2. **Identification** — sha256 / filename / size / format / arch, plus language / compiler / packer
   (from `bind_check` + `image`).
3. **Capabilities** — the core, organized **by behavior** (execution, persistence, privilege-escalation,
   defense-evasion, credential-access, discovery, collection, cryptography, command-and-control,
   exfiltration, impact) — **not cluster by cluster.** Synthesize; do not echo the map's structure.
4. **Details** — a comprehensive technical walkthrough of the **entire** malware: its execution flow from
   entry through every major component, covering the full binary (not only the headline behaviors), each
   with the function RVAs and decompiled evidence behind it. This is the in-depth analysis; the
   Capabilities section is its behavioral summary.
5. **Host-based indicators** — files, registry keys, mutexes, services, processes, paths.
6. **Network-based indicators** — C2 endpoints, URLs, protocols, ports.
7. **MITRE ATT&CK** — technique-ids mapped to the behaviors you confirmed.
8. **Conclusion** — overall assessment, likely family/attribution if evident, and your confidence.

**Evidence discipline, applied inline (this is where the gate lives):**
- Every capability and IOC is written in behavioral terms and **carries the function RVA (at its call
  site) whose decompiled body proves it** — inline, e.g. *"encrypts victim files with ChaCha20
  (member `0x…` in cluster `0xea390`)"* — never a bare claim, never citing only the cluster root.
- **State an xrefer hypothesis only after you confirm it in a body.** One you could not verify is either
  omitted or flagged inline as "unconfirmed" — never laundered as fact (its `xrefer_llm_guess` tag does
  not become truth by being repeated).
- **Report ALL cryptography** from `dependency_bom` (§2b): name every cipher and say which is primary vs
  secondary from the bodies you read; a statically-linked crypto crate is a finding, not noise.
- Pivot IOCs via `get_context_for_hash` / `get_ioc_assessment`; drop noisy ones.

**Coverage is internal discipline, not a section:** investigate every `investigation_queue` item before
writing, and do not assert "benign"/complete while any `coverage.omitted.notable_rvas` RVA is unread —
but this governs your *analysis*; it is not something you print.

## 7. Identity, degraded mode, anti-patterns

- **Cluster identity is `root_rva`.** A cluster `llm.relationships` string may name other clusters as
  run-local `cluster.id.NNNN` tokens — never use those as stable keys, and do not invent an edge from
  the prose; identity is always `root_rva`.
- **Degraded (`meta.has_llm_layer:false`):** `verdict`, every cluster `llm` block, and `llm_lib`
  collapse to null; the queue is scored purely on static signals. The static skeleton (clusters,
  reachability, artifacts+call_site_rvas, danger_floor, coverage.omitted) is still a complete
  Step-2/3 accelerator — proceed on structure and derive the verdict yourself.
- Do NOT: report from the paste (any capability without a body quote); treat `noise`/omission as
  "already triaged"; conclude "clean" with unread `notable_rvas`; use a run-local `cluster.id.NNNN`
  token as a key; assume the base equals `image_base`.

## Fields NOT in this format (do not look for them)

To keep the single file pasteable, an anatomy JSON deliberately omits: decompiled code, cluster call
graph `edges` (recover with `r2_callees` from the root), the full entity catalog (`entities[]` is
referenced-only), staged rename/comment suggestions, crypto carve-target blobs, and any binary-level
prose report. Per-function `artifacts.libs` and `dependency_bom` ARE present, but filtered to
cluster-local (signal) crates — pervasive runtime crates are collapsed into `dependency_bom.pervasive`.
When you need the omitted material or the unfiltered per-function `libs`, use the tiered
`xrefer-agent-map` bundle (its `clusters/<root_rva>.json` carries edges + full artifacts, and
`indices/` carries the reverse index, reachability, and full entity catalog; `map.json.dependency_bom`
mirrors this BOM with `entity_idxs`).
