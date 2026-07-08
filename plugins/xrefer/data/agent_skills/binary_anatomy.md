---
name: binary_anatomy
description: >-
  Consume an xrefer "binary anatomy" — a single, chat-pasteable JSON map of a native binary
  (recognizable by _readme.format == "xrefer-binary-anatomy" and the _end.sentinel
  "XREFER_ANATOMY_EOF"). It is a pre-computed investigation PLAN: a ranked queue of the functions
  that matter and the exact addresses to decompile, plus xrefer's interpretations as null-verdict
  hypotheses. Activate when format_binary has an anatomy JSON for the sample's sha256. It never
  replaces reading bodies: every claim still requires an r2_decompile (or r2_disasm when that fails).
---

# binary_anatomy — consuming a single-file xrefer map

## Prerequisite

Confirm the **`malware_analysis`** and **`format_binary`** skills are active in this session, and
**activate them if they are not.** This skill only augments them: `malware_analysis` owns the report
format and RE doctrine, `format_binary` drives radare2, this map pre-computes their triage. Say so if
they are unavailable.

## What this is

A **plan, not an analysis.** It ranks where to point radare2 first and what to expect; it carries **no
decompiled code**. Building a report by quoting the paste is the "listing is not reverse engineering"
failure. It fast-forwards triage and pivots and drops you into the real work: reading bodies.

## 1. Before you touch r2 — intact + bound (fail-closed)

- **Intact:** the raw text must end with `_end.sentinel == "XREFER_ANATOMY_EOF"`. If not, it was
  truncated in transit — ask for a re-paste (or the tiered bundle for a big binary); do not analyze a
  fragment. `_end.declared_bytes` is the intended byte length.
- **Bound:** `r2_init_project` the sample and read r2's **real** baddr. **If `bind_check.sha256` != your
  sample's sha256, REFUSE** — wrong sample. Then every address is `r2_addr = r2_baddr + rva` (do NOT
  assume baddr == `bind_check.image_base`). If `bind_check.expected_bytes_hex` is present, probe it at
  `r2_baddr + check_anchor_rva`; on mismatch, REFUSE — never `r2_decompile` or `r2_rename` (a
  wrong-sample rename is a destructive write).

## 2. Provenance — static is fact, llm is a hypothesis

- **Bare values = STATIC ground truth** you may state as fact: RVAs, imports/strings/capa names,
  `call_site_rvas`, `reachability`, `danger_floor`, `artifacts.libs` (linked crate refs), and the static
  skip signals `category=="func_lib"` / `is_simple_api_thunk`.
- **`{"v": …, "src": "xrefer_llm_guess"}` = a HYPOTHESIS** (the `verdict`, each cluster's `llm` block,
  `llm_lib`). It confirms nothing until you read the body. Cluster `llm_lib` and per-function `origin`
  are LLM-derived too — never skip a function on them; the only static skip signal is `category=="func_lib"`.

## 3. THE CORE LOOP — work the queue, decompile recursively, disassemble on failure

This is the whole job. `investigation_queue` is xrefer's ranked shortlist; **`static_score` is the
ORDER you work in, not a license to skip.** Take every item to a resolution (confirmed /
dismissed-with-evidence / blocked) before you write. For each queue item:

1. **Open its cluster** in `clusters[]` (match `root_rva == ref_rva`). `first_move` is the ready call.
2. **Decompile the root AND every `must_read_rvas`** (= the cluster's `llm.verify_against.key_function_rvas`
   — the artifact-bearing members that actually make the calls), jumping to each function's
   `artifacts.*.call_site_rvas`. **The root alone is never a disposition** — it is usually a dispatcher;
   the behavior lives in a member or deeper.
3. **Recurse down the call chain.** The single file drops cluster `edges` for size, so from each function
   `r2_callees` and **decompile the callees too**, stepping into any child that consumes data you care
   about — keep going until a leaf body actually *proves* the behavior. `static.functions_omitted > 0`
   tells you members were dropped; recover them the same way. Do not stop at depth 1.
4. **On decompile failure, disassemble.** When `r2_decompile` errors or returns garbage on a function
   (r2ghidra can choke on obfuscated/odd code), fall back to **`r2_disasm`** for that function and read
   the assembly; use `r2_get_bytes` / `r2_get_string` for data at a `call_site_rva`. **Never leave a
   must-read function uncovered just because the decompiler failed** — mark it blocked only if both fail.
5. **Skip a function only on the STATIC signals** `category=="func_lib"` / `is_simple_api_thunk`. Never
   on LLM library framing — it can hide a mislabeled payload.

**The gate:** no capability sentence in your report without a decompiled (or disassembled) body behind
it, cited at its member RVA. Only after reading the bodies may you repeat the cluster's
`label`/`description`/`mitre`.

## 4. Supporting fields — map them in as you go

| field | what it gives you | use it to |
|---|---|---|
| `investigation_queue[].must_read_rvas` | the bounded depth floor per cluster | the functions you MUST decompile |
| `reachability.via_path_rvas` / `min_depth` | entry→root shortest path | find the trigger (second-to-last node = the caller) |
| `danger_floor` (on a cluster/queue item) | reaches injection/crypto/net-exfil/cred-access imports | a hard must-read; never skip |
| `indirect_artifact_count` | artifacts reachable via callees | spot the dispatcher/hub — read it first |
| `static.subcluster_refs[]` | `at_node_rva → child_cluster_id` | real call linkages into child clusters |
| `artifacts.libs` | linked crate refs at call sites | crypto/deps evidence (see below) |
| `entities[]` | referenced-only catalog | resolve an `entity_idx` to a name |
| `_readme.counts` / `coverage.omitted` | how much of the binary this file covers | see §5 |

**Crypto note (anti-tunnel-vision):** when a cluster's `artifacts.libs` shows cipher crates, report
**every** one, not just the loudest — a ransomware build routinely links several (e.g. `chacha20` +
`aes` + `ctr` for the file encryptor, `rsa` for key wrapping). Decide primary vs secondary from the
bodies, not from frequency. A linked crypto crate is evidence, not noise, even with a null `danger_floor`.

## 5. What you may skip, and what you must not

- **`noise` is the only budget lever.** `noise.static_lib_*` (all members are static FUNC_LIB) is safe to
  leave unread. `noise.llm_lib_demoted` you MAY leave unread to save budget — but it is visible, not
  triaged; open one if a lead points into it. **Never** treat an `investigation_queue` item as skippable.
- **`coverage.omitted.notable_rvas`** lists omitted clusters that STATICALLY reach a danger floor
  (this file caps to the top-N by score). You **must r2-triage every one** before any "benign"/complete
  verdict. If you suspect crypto/networking the map does not surface, confirm with `r2_imports` /
  `r2_find_regex` — do not assume absence.
- `promoted_from_noise:true` = a cluster the LLM called "library" that statically reaches the danger set;
  already force-kept in the queue. Never skip on the LLM flag when a static `danger_floor` disagrees.

## 6. The deliverable — a malware analysis report (NOT a verification log)

Follow `report_scaffold`. Produce a **standard malware analysis report in your `malware_analysis`
format** — an intelligence product, not a table of what you verified. **Do not emit a disposition
ledger or a coverage header**; verification lives *inside* the report as the evidence attached to each
finding. Sections (`report_scaffold.sections`): **executive summary → identification → capabilities
(organized by behavior, not cluster) → details (a full technical walkthrough of the entire malware,
component by component) → host-based indicators → network-based indicators → MITRE ATT&CK → conclusion.**
- Every capability and IOC carries, inline, the **member** RVA (at its call site) whose body proves it —
  never a bare claim, never only the cluster root.
- State an xrefer hypothesis only after confirming it in a body; omit or mark "unconfirmed" the rest.
- Report ALL cryptography from `artifacts.libs`; pivot IOCs via `get_context_for_hash` / `get_ioc_assessment`.
- **Coverage is internal discipline, not a section:** cover every queue item and every
  `coverage.omitted.notable_rvas` RVA before you write — but this governs your analysis, it is not printed.

## 7. Degraded mode & anti-patterns

- **Degraded (`meta.has_llm_layer:false`):** `verdict`, every `llm` block and `llm_lib` are null; the
  queue is scored on static signals only. The static skeleton (clusters, reachability, artifacts + call
  sites, danger_floor, coverage.omitted) is still a complete accelerator — work the queue and derive the
  verdict yourself.
- **Do NOT:** report from the paste (any claim without a body); stop at a cluster root; skip a must-read
  because the decompiler failed (disassemble instead); treat `noise`/omission as triaged; conclude
  "clean" with unread `notable_rvas`; assume baddr == `image_base`.

## Not in this file (do not look for them)

To stay pasteable, an anatomy JSON omits: decompiled code, cluster `edges` (recover with `r2_callees`),
the full entity catalog (`entities[]` is referenced-only), rename/comment suggestions, any prose report,
and any binary-wide dependency inventory. `artifacts.libs` is present but only for the shown top-N
clusters (crates used only by unclustered/below-cap code are absent). For the omitted material use the
tiered **`xrefer-agent-map`** bundle (its dossiers carry `edges` + full artifacts; `indices/` carries the
reverse index, reachability, and full entity catalog).
