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
  `coverage.omitted.notable_rvas`, and the static per-function skip signals `category=="func_lib"` /
  `is_simple_api_thunk`. You may state these as fact.
- **Any object shaped `{"v": ..., "src": "xrefer_llm_guess"}` = a HYPOTHESIS.** Every LLM value is
  wrapped this way (the `verdict` block, each cluster's `llm` block, `llm_lib`). The `src` tag travels
  with the value even if you lift a sub-object in isolation, so a quoted `"keylogger"` still shows it
  is a guess. It confirms nothing until you read the body.
- **NOT static, despite looking plain:** cluster `llm_lib` and (in the cluster `llm` block) any
  library framing inherit the LLM `library_or_runtime` verdict. Never treat them as skip authority.

## 3. The capability gate — ALWAYS applies (`_readme.capability_gate_applies` is always true)

**No capability sentence in your report without a decompiled body behind it.** For each cluster's
`llm.verify_against.key_function_rvas`, `r2_decompile` every RVA, read the body, and only then may you
repeat the cluster's `label`/`description`/`mitre`. This holds in degraded mode too: with
`meta.has_llm_layer == false` there are no hypotheses to confirm, but `investigation_queue[].why` and
the static evidence are still only LEADS (where to point r2), never findings.

## 4. The loop

Walk `investigation_queue` — a ranked to-do list, each item's `first_move` is a literal starting r2
call and `ref_rva` is the cluster root (= the address to `r2_decompile`). For each item:
- Open the matching entry in `clusters[]` (match `root_rva == ref_rva`).
- `r2_decompile` its `static.functions`, jumping to each function's `artifacts.*.call_site_rvas` (the
  exact instructions). **Skip a function only on the STATIC signals** `category=="func_lib"` /
  `is_simple_api_thunk` unless a lead points in. Do NOT skip on library framing from the LLM layer —
  it can hide a mislabeled malicious function.
- `indirect_artifact_count` on a function marks a behavior-gating hub/dispatcher — high count = read
  it first.
- `reachability.via_path_rvas` is one static path from entry to the root; `n_paths` is how many exist.
- `static.subcluster_refs[].at_node_rva`→`child_cluster_id` are real call linkages (trustworthy).
- Use `llm.verify_against.key_function_rvas` as the must-read set and `llm.mitre[].rationale` as the
  claim to confirm. Note `static.functions_omitted` > 0 means the single file dropped low-signal
  members of this cluster — the tiered bundle (or `r2_callees` from the root) has the rest.

## 5. Anti-hiding — you cannot conclude "clean" on a curated map

A single file can't hold a big binary, so clusters are curated and library-demoted. The safety net is
**static**, not the LLM's opinion:
- `coverage.omitted.notable_rvas` lists, by RVA, every omitted cluster that **statically** reaches a
  danger floor (process-injection / crypto / net-exfil / cred-access imports). You **must r2-triage
  every one** before any completeness or "benign" verdict (see `coverage.omitted.note`).
- `noise.promoted_out`, and any queue/cluster item with `promoted_from_noise:true`, are clusters the
  LLM called "library" but that statically reach the danger set — treat them as normal queue items.
- `noise.static_lib_count` / `static_lib_sample_rvas` (every member hit the static FUNC_LIB/thunk
  path) is deterministic library code, collapsed to a count — safe to skip.
- `noise.llm_lib_demoted` (LLM `library_or_runtime` guess, `{v,src}`-tagged, NOT statically confirmed)
  is the budget lever: you **MAY skip these to save decompiler budget** — that is their purpose — **but
  they are visible, not triaged.** Analyze one if budget allows, a lead points into it, or it shows up
  in `coverage.omitted.notable_rvas`. Any llm_lib cluster reaching a danger floor is already
  force-promoted (`promoted_out`), so a payload the LLM mislabeled "library" cannot hide here. Never
  skip on the LLM library flag when a static danger signal disagrees.

## 6. OUTPUT CONTRACT (this is where the gate is enforced)

Follow `report_scaffold.output_contract`. Your report is checkable by re-reading it:
1. **First block is a coverage header**, computed from the functions you actually decompiled — e.g.
   *"Coverage: 4 clusters confirmed via r2 / 15 shown / N omitted (unread danger-floor RVAs: none)."*
   An agent that skipped decompiling shows "0 confirmed" and the incompleteness is visible.
2. **Every capability sentence quotes the decompiled body excerpt at its cited RVA.** No body quote,
   no claim.
3. **Attribute every hypothesis:** "xrefer proposed X; I confirmed via r2_decompile @RVA" or "xrefer
   proposed X; UNCONFIRMED" — never a bare `xrefer_llm_guess` value as fact.
4. **No "benign"/completeness** while any `coverage.omitted.notable_rvas` RVA is unread.
5. Speak MITRE technique-ids for the TTP section; pivot IOCs via `get_context_for_hash` /
   `get_ioc_assessment` and drop noisy ones. List unverified xrefer hypotheses explicitly.

## 7. Identity, degraded mode, anti-patterns

- **Cluster identity is `root_rva`.** `run_ref` (`cluster.id.NNNN`) is run-local — never a stable key.
  A cluster `llm.relationships` string may name other `cluster.id.NNNN`; resolve those to a root
  yourself only via the tiered bundle's resolver — do not invent an edge from prose.
- **Degraded (`meta.has_llm_layer:false`):** `verdict`, every cluster `llm` block, and `llm_lib`
  collapse to null; the queue is scored purely on static signals. The static skeleton (clusters,
  reachability, artifacts+call_site_rvas, danger_floor, coverage.omitted) is still a complete
  Step-2/3 accelerator — proceed on structure and derive the verdict yourself.
- Do NOT: report from the paste (any capability without a body quote); treat `noise`/omission as
  "already triaged"; conclude "clean" with unread `notable_rvas`; use `run_ref` as a key; assume the
  base equals `image_base`.

## Fields NOT in this format (do not look for them)

To keep the single file pasteable, an anatomy JSON deliberately omits: decompiled code, cluster call
graph `edges` (recover with `r2_callees` from the root), per-function `libs` artifacts, the full
entity catalog (`entities[]` is referenced-only), staged rename/comment suggestions, crypto
carve-target blobs, and any binary-level prose report. When you need those, use the tiered
`xrefer-agent-map` bundle (its `clusters/<root_rva>.json` carries edges + full artifacts, and
`indices/` carries the reverse index, reachability, and full entity catalog).
