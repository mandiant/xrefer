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

"""DSPy modules with structured inputs and Pydantic outputs."""

import enum
from typing import Any, ClassVar, Dict, List

import dspy
from pydantic import BaseModel, Field, field_validator, model_serializer, model_validator


# Substrings flagged in BinaryReport text. The list seeds a SOFT
# post-hoc warning in ClusterAnalyzer (see _warn_on_binary_report_issues)
# — it does NOT fail validation. Earlier iterations enforced this list
# via a @model_validator on BinaryReport; that turned every LLM slip
# into a catastrophic analysis abort, which is the wrong trade-off.
# Prompt guidance now does the heavy lifting; the soft warning catches
# slips so the analyst knows.
#
# Marketing adjectives bias prose toward unfounded authority — concrete
# facts ('32 file extensions' rather than 'comprehensive list') carry
# the information without the puffery. The ``cluster.id.`` form belongs
# in per-cluster ``relationships``, not in the binary-level narrative.
#
# Hedging tokens (likely / appears to / may / possibly / seems /
# suggesting / suggests / presumably) are INTENTIONALLY NOT included.
# Both origin/main and origin/gsoc_2025 use hedge tokens in their own
# instructions; analyst prose uses them to signal inference vs.
# observation, and banning them would force false certainty.
BANNED_TOKENS_SOFT = (
    # marketing adjectives (vibes, not facts)
    "sophisticated", "advanced", "powerful", "comprehensive", "extensive",
    "highly optimized", "highly advanced", "robust", "complex",
    "specialized", "distinctive",
    # cross-cluster leak — structural, not stylistic
    "cluster.id.",
)


class BinaryReport(BaseModel):
    """Binary-level analysis report rendered as markdown for the
    analyst.

    INTENTIONALLY MINIMAL SHAPE — just two top-level fields:

    - ``overview``: a paragraph stating what the binary is.
    - ``details``: free-form markdown for the rest of the analysis.

    The earlier schema enforced ``behavior: List[BehaviorSection]``
    with narrow verb-phrase headings, plus a separate ``observed
    artifacts`` list with a fixed enum-typed label. That structure
    pushed the LLM toward narrow per-section observations and
    suppressed the comprehensive synthesizing narrative style that
    analyst-grade triage reports actually use. The fix is to keep the
    fixed top-level structure (Overview + Details) and let the LLM
    pick its own ``###`` sub-headings inside Details, driven by what
    the binary actually does. When the data contains observable
    indicators of compromise, they go as a final ``### Indicators of
    Compromise`` sub-section inside Details (see signature docstring
    for format).

    Serializes to a markdown string for downstream consumers via
    ``to_markdown()`` — the renderer at ``data/report_tmpl.html`` and
    the IDA-side surfaces both consume ``binary_report`` as a string,
    so the outer ``ClusterAnalysisResponse`` serializer flattens this
    model on ``model_dump()``.
    """

    overview: str = Field(
        ...,
        description=(
            "One paragraph opening with 'The binary is a "
            "<morphology>...' (where <morphology> is the "
            "binary_category) with no adjectives between 'is' and "
            "the morphology: write 'The binary is a ransomware "
            "that...', NOT 'The binary is a highly structured "
            "ransomware...'. For binary_category=Undetermined, use "
            "a neutral noun describing what the binary does (e.g., "
            "'The binary is a CRC32 utility...'). State the "
            "strongest takeaway. No bullets. Code spans (`like "
            "this`) are permitted; no other markdown. Prefer "
            "concrete claims over puffery throughout — avoid "
            "vibes-only adjectives like 'sophisticated', "
            "'advanced', 'comprehensive', 'robust', 'complex'."
        ),
    )
    details: str = Field(
        ...,
        description=(
            "Comprehensive technical report as markdown. Use `###` "
            "sub-headings to organise the analysis around the "
            "binary's behaviours and observed characteristics — "
            "there is no fixed list of sub-section names.\n"
            "\n"
            "Cover EVERY observation the cluster_data supports — "
            "behavioural AND technical: every cluster's "
            "functionality, every library, protocol, algorithm, "
            "configuration setting, runtime identifier, plus any "
            "toolchain / packer / anti-analysis / build-metadata / "
            "language / encoding cues the artifacts surface. "
            "Default to inclusion: if an observation is grounded in "
            "cluster_data, include it; omit only when speculative "
            "or unsupported. Be exhaustive within sub-sections — "
            "if 32 file extensions are observed, list all 32; if "
            "three encryption algorithms, name each.\n"
            "\n"
            "Quote concrete strings VERBATIM in backticks: domains, "
            "IPs, paths, registry keys, mutex names, user-agents, "
            "library names, CLI flags, hardcoded commands. Do not "
            "generalise ('uses a mutex named `filemanager1`' not "
            "'uses a mutex'). Prefer concrete facts over puffery: "
            "'lists 32 file extensions' beats 'comprehensive list'; "
            "'4 hardcoded C2 domains' beats 'sophisticated network "
            "communication'. Avoid vibes-only adjectives like "
            "'sophisticated', 'advanced', 'comprehensive', 'robust', "
            "'complex'.\n"
            "\n"
            "End with a final sub-section listing the binary's "
            "observable runtime identifiers (hardcoded values a "
            "defender could pivot on) when any exist, formatted "
            "as ``- **<Label>**: `<value>` [c<N>]`` lines.\n"
            "\n"
            "Use the following canonical labels for common IoC "
            "categories when their values appear in the cluster "
            "artifacts. The label shown is the **bold label** "
            "in the bullet — use it verbatim so the inventory "
            "stays consistent across reports:\n"
            "  - Network: `Domain`, `IP`, `URL`, `URL Path`, "
            "`User-Agent`, `HTTP Header`\n"
            "  - File-system: `File Path`, `Directory`, `File "
            "Name`, `File Extension`, `File Pattern` "
            "(glob / regex)\n"
            "  - Registry (Windows binaries): `Registry Key`, "
            "`Registry Value` (use this for distinctive value "
            "names, not for the value's data)\n"
            "  - Execution: `Command` (full command lines such "
            "as `vssadmin.exe Delete Shadows /all /quiet`), `CLI "
            "Flag` (flags the binary's OWN command-line parser "
            "accepts), `Binary Name` (referenced, dropped, or "
            "spawned external binaries such as `psexec.exe`, "
            "`bcdedit.exe`), `Service` (service names created "
            "or queried), `Scheduled Task`\n"
            "  - IPC / synchronization: `Mutex`, `Named Pipe`, "
            "`Event`\n"
            "  - COM / WMI / UI: `COM CLSID` (formatted "
            "`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`), `WMI "
            "Query`, `Window Title`, `Window Class`\n"
            "  - Build / metadata: `PDB Path`, `Version` (build "
            "or version strings)\n"
            "\n"
            "The list above is the baseline — emit any category "
            "whose value(s) appear in the cluster artifacts, AND "
            "add any other distinctive hardcoded value defenders "
            "could pivot on (the list is not exhaustive). Do NOT "
            "pad with values that aren't actually in the "
            "artifacts.\n"
            "\n"
            "Do NOT list imported APIs or library/DLL names in "
            "this sub-section — those are usage observations, "
            "not hardcoded detection artifacts a defender can "
            "search for; APIs and libraries belong in the prose "
            "body where they describe behaviour.\n"
            "\n"
            "Title it `### Indicators of Compromise (IoCs)` when "
            "binary_category is explicitly malicious (anything "
            "other than Undetermined, Utility, Remote Control "
            "and Administration Tool, Archiver, Sniffer, "
            "Cryptocurrency Miner, Decoder, Decrypter, Screen "
            "Capture Tool, Reconnaissance Tool, Builder); "
            "otherwise title it `### Observable Runtime "
            "Artifacts`. Omit this sub-section only when the "
            "binary has no such identifiers at all.\n"
            "\n"
            "Where prose needs a subject for the binary, refer to "
            "it using a short natural noun form of binary_category "
            "rather than the generic 'the binary' (e.g. 'the "
            "ransomware', 'this stealer', 'the miner', 'the "
            "backdoor'). For multi-word categories use a natural "
            "short form (e.g. 'this tool' for 'Remote Control and "
            "Administration Tool'). For binary_category="
            "Undetermined, fall back to 'the binary' or 'this "
            "binary'. Verbs without a subject are also fine (e.g. "
            "'Initialises the runtime environment...'); apply the "
            "morphology noun only where a subject is required.\n"
            "\n"
            "Markdown allowed: `###`, `####`, `-`, `**bold**`, "
            "`` `inline code` ``. No `##` (top-level structure is "
            "fixed), no code fences, no tables.\n"
            "\n"
            "CITATION COVERAGE (applies to `## Details` sub-"
            "sections; `## Overview` is exempt; the IoC / "
            "Observable Runtime Artifacts sub-section follows a "
            "simplified per-bullet rule defined below):\n"
            "\n"
            "Every prose sentence in `## Details` sub-sections "
            "must be covered by exactly one citation group. No "
            "prose sentence may exist without a citation behind "
            "it. The boundary where one citation ends marks where "
            "the next begins; there are no uncited gaps.\n"
            "\n"
            "A citation group may span ONE or MORE consecutive "
            "sentences that share the same evidentiary basis. "
            "Place a single citation token at the end of the LAST "
            "sentence in the group, before the period. Do not "
            "repeat the same citation on every sentence inside a "
            "group — one token per group.\n"
            "\n"
            "Token forms: single cluster `[c5]`; multiple "
            "`[c4, c6]` or `[c4, c6, c7]`. Cap at three clusters "
            "per citation. If a claim genuinely involves four or "
            "more clusters, the claim is too broad — split it "
            "into narrower per-phase claims, each with its own "
            "focused citation. Use the smallest accurate set: "
            "include a cluster ID only when that cluster actually "
            "carries evidence for the claim; each ID in the "
            "bracket must be defensible if challenged. The long "
            "form `cluster.id.NNNN` remains forbidden in "
            "binary_report — use only the short `[c<N>]` citation "
            "form. Bullet points follow the same rule as "
            "sentences: each bullet ends with a citation covering "
            "its claim.\n"
            "\n"
            "ALLOWED examples:\n"
            "  - Single cluster, one sentence: \"Captures the "
            "desktop using GDI+ via `BitBlt` and stages the "
            "bitmap in a memory buffer [c5].\"\n"
            "  - Single cluster, multi-sentence group: \""
            "Locates Chrome and Firefox profile directories. "
            "Reads the `Login Data` SQLite database via "
            "`sqlite3_open` and `sqlite3_exec` [c4].\"\n"
            "  - Multi-cluster, one sentence: \"Decrypts stored "
            "browser credentials using Windows DPAPI via "
            "`CryptUnprotectData` [c4, c6].\"\n"
            "  - Three-cluster citation: \"The orchestrator "
            "dispatches between credential harvesting, screen "
            "capture, and network exfiltration [c2, c4, c5].\"\n"
            "\n"
            "NOT ALLOWED:\n"
            "  - Uncited prose: \"The remainder of this report "
            "walks through major behaviours.\" — framing-only "
            "sentences with no citation must be deleted or merged "
            "into the next substantive statement under its "
            "citation.\n"
            "  - Partial coverage: \"Captures the desktop using "
            "GDI+. Encodes the bitmap [c5].\" — the first "
            "sentence has no citation backing it; group both "
            "under one citation at the end, or cite each "
            "separately.\n"
            "  - Over-citation (padding): \"Encrypts files using "
            "AES-256-CBC [c1, c2, c3, c4, c5].\" — only the "
            "actual encryptor cluster belongs here; the rest "
            "fail the defensibility test.\n"
            "  - Over-citation (claim too broad): \"Performs the "
            "full attack lifecycle [c2, c4, c5, c6, c7, c9].\" — "
            "six clusters under one claim means the claim is too "
            "broad; split into narrower per-phase claims.\n"
            "\n"
            "IoC / Observable Runtime Artifacts bullets each "
            "carry ONE citation, placed at the end of the bullet "
            "line. Format: ``- **<Label>**: `<value>` [c<N>]``. "
            "Most IoCs come from a single cluster (the cluster "
            "whose artifacts contain the hardcoded value), so the "
            "citation is typically single-cluster. Multi-cluster "
            "citations like `[c4, c5]` are valid when the value "
            "genuinely spans clusters (e.g. a mutex created in "
            "one cluster and checked in another). Do NOT group "
            "citations across bullets — each bullet carries its "
            "own citation even when consecutive bullets cite the "
            "same cluster.\n"
            "\n"
            "Self-check before emitting JSON: scan every prose "
            "sentence and every IoC bullet in `## Details` sub-"
            "sections. For each prose sentence, confirm one of: "
            "it ends with a citation token covering its claim, "
            "OR it is followed (without any uncited intervening "
            "sentence) by a sentence that ends with a citation "
            "covering the same claim. For each IoC bullet, "
            "confirm it ends with a single citation identifying "
            "the source cluster. If any sentence or bullet is "
            "uncited, either cite it or remove it. For each "
            "citation, confirm every cluster ID in the bracket is "
            "defensibly evidentiary. No exceptions."
        ),
    )

    @field_validator("overview")
    @classmethod
    def _opener(cls, v: str) -> str:
        if not (v.startswith("The binary is ") or v.startswith("This binary is ")):
            raise ValueError(
                "overview must open with 'The binary is ' or "
                "'This binary is '"
            )
        return v

    # NOTE on banned tokens. Earlier iterations enforced a marketing-
    # adjective + cluster.id. ban via a @model_validator that raised
    # on any match. That validator caused real analyses to abort when
    # the LLM used a single banned word in an otherwise-rich report.
    # The ban is now a SOFT post-hoc warning in ClusterAnalyzer
    # (see _warn_on_binary_report_issues) — the prompt asks the LLM
    # to prefer concrete facts over marketing adjectives, and the
    # warning surfaces slips without aborting the analysis.

    # Length is INTENTIONALLY NOT validated. Earlier iterations had a
    # hard [1500, 4500] floor/ceiling validator on the rendered total
    # AND a min_length=200 on `overview`; both failed real analyses
    # on small, simple binaries (and on terse-but-accurate LLM
    # responses for any binary). Pydantic field-level / model-level
    # length constraints aren't reflected in the JSON schema the LLM
    # sees in a way that makes the LLM able to aim for them
    # reliably, so a hard floor/ceiling on length is a contract the
    # model can violate without warning, and DSPy doesn't retry on
    # Pydantic ValidationError in this path — the whole analysis
    # aborts.
    #
    # Length expectations now live as TARGETS in the LLM-visible
    # docstring on ClusterAnalyzerSignature (so the model can read
    # and aim for them), with non-fatal post-hoc warnings in
    # ClusterAnalyzer.analyze_clusters if the produced report falls
    # well below or above the target band. The constants below feed
    # the warning logic.
    SOFT_MIN_LENGTH: ClassVar[int] = 1500
    SOFT_MAX_LENGTH: ClassVar[int] = 4500

    def to_markdown(self) -> str:
        """Render this BinaryReport back to the markdown subset the
        renderer parses. Top-level structure is fixed: `## Overview`
        then `## Details`. Sub-structure inside Details is whatever
        the LLM emitted.
        """
        return (
            "## Overview\n\n"
            f"{self.overview.rstrip()}\n\n"
            "## Details\n\n"
            f"{self.details.rstrip()}\n"
        )


class CategoryAssignment(BaseModel):
    """Single categorization mapping entry.

    Representing assignments as a list of explicit objects keeps the JSON
    schema valid for Gemini (which rejects objects with no properties) while we
    serialize back to the legacy mapping shape for the rest of the codebase.
    """

    item_index: int = Field(..., description="Original index of the item in the input list")
    category_index: int = Field(..., description="0-based index of the assigned category")

class CategorizationResponse(BaseModel):
    """Response model for API/Library categorization."""

    category_assignments: List[CategoryAssignment] = Field(..., description="List of item/category mappings; use item_index and category_index fields")

    @model_validator(mode="before")
    def _coerce_legacy_mapping(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        """Allow existing dict-shaped payloads (backward compatibility)."""
        assignments = value.get("category_assignments") if isinstance(value, dict) else None
        if isinstance(assignments, dict):
            value["category_assignments"] = [
                {"item_index": int(idx), "category_index": cat_idx}
                for idx, cat_idx in assignments.items()
            ]
        return value

    @model_serializer(mode="wrap")
    def _serialize_as_mapping(self, handler):
        """Return the legacy mapping shape when dumping."""
        data = handler(self)
        mapping = {
            str(entry["item_index"]): entry["category_index"]
            for entry in data.get("category_assignments", [])
        }
        data["category_assignments"] = mapping
        return data


class CategorizerSignature(dspy.Signature):
    """
    Guidelines for categorization:

    - File and Path I/O: Functions or modules that directly read from or write to files, handle file descriptors, or deal with file/directory paths. Look for keywords like `File`, `Dir`, `Path`, `Read`, `Write`, `Open`, `Close`, `Delete`, `Move`, `Copy`, `Rename`, `fs`, `io`, `stream`, `buffered`, `reader`, `writer`.

    Examples:
      - API Functions: `CreateFileW`, `ReadFile`, `WriteFile`, `DeleteFile`, `OpenDir`.
      - Library Functions: `std::io::stdio`, `std::fs::read_to_string`, `configparser::ini`, `awsconfig::fsutil`, `hyper::body::tobytes`.

    - Registry Operations: Functions or modules that create, open, query, modify, or delete entries in configuration registries or settings. Look for prefixes like `Reg`, or terms like `Registry`, `Config`, `Settings`, `Preferences`.

    Examples:
      - API Functions: `RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`.
      - Library Functions: `registry::open`, `registry::query`.

    - Network I/O: Functions or modules for network communication, socket operations, or network resource management. Look for keywords like `Socket`, `Connect`, `Send`, `Recv`, `Bind`, `Listen`, `Accept`, `Network`, `Net`, `HTTP`, `TCP`, `UDP`, `URI`, `IP`, `Request`, `Response`, `Client`, `Server`, `Protocol`.

    Examples:
      - API Functions: `socket`, `connect`, `send`, `recv`, `bind`, `NetServerEnum`.
      - Library Functions: `std::net::ip`, `reqwest::async_impl::client`, `hyper::client::pool`, `h2::proto::peer`, `tokio::net::TcpStream`, `core::net::parser`.

    - Process/Thread Operations: Functions or modules that create, modify, or interact with processes or threads, including concurrency primitives, task scheduling, and synchronization mechanisms. Look for terms like `Process`, `Thread`, `Task`, `Async`, `Await`, `Spawn`, `Join`, `Mutex`, `Semaphore`, `Lock`, `Channel`, `Queue`, `Executor`, `Scheduler`, `Park`, `Waker`.

    Examples:
      - API Functions: `CreateProcessW`, `TerminateProcess`, `CreateThread`, `WaitForSingleObject`.
      - Library Functions: `std::thread::spawn`, `tokio::task::state`, `std::sync::Mutex`, `parking_lot::Mutex`, `crossbeam_channel::channel`, `tokio::runtime::Handle`.

    - Memory Management: Functions or modules for allocating, freeing, or manipulating memory. Look for keywords like `Alloc`, `Free`, `ReAlloc`, `Memory`, `Mem`, `Heap`, `Buffer`, `Pool`, `Arena`, `Box`, `Rc`, `Arc`, `Clone`.

    Examples:
      - API Functions: `HeapAlloc`, `HeapFree`, `VirtualAlloc`, `malloc`, `free`.
      - Library Functions: `alloc::vec::Vec`, `typed_arena::Arena`, `bytes::BytesMut`, `core::slice::from_raw_parts`, `slab::Slab`.

    - System Information: Functions or modules that retrieve system, environment, or user data, including service management, user authentication, and system configuration. Look for keywords like `GetSystem`, `GetUser`, `GetEnv`, `Sys`, `Info`, `Config`, `Env`, `Service`, `Logon`, `Hostname`, `OS`, `Platform`, `Version`.

    Examples:
      - API Functions: `GetSystemInfo`, `GetUserNameW`, `LogonUserW`, `OpenSCManagerW`.
      - Library Functions: `std::env::vars`, `whoami::username`, `sys_info::os_type`, `awsconfig::meta::region`.

    - User Interface: Functions or modules related to GUI elements, user interaction, console operations, or terminal manipulation. Look for terms like `Window`, `Message`, `Console`, `Cursor`, `Event`, `Input`, `Output`, `UI`, `GUI`, `Dialog`, `Prompt`, `Terminal`, `Render`, `Display`.

    Examples:
      - API Functions: `MessageBoxW`, `WriteConsoleW`, `SetCursorPos`.
      - Library Functions: `crossterm::terminal`, `tui::widgets::list`, `dialoguer::prompts::select`, `anstyle::color`.

    - Cryptography: Functions or modules related to cryptographic operations like hashing, encryption, decryption, key generation, or random number generation. Look for keywords like `Crypt`, `Hash`, `Encrypt`, `Decrypt`, `Random`, `Cipher`, `RSA`, `AES`, `SHA`, `Key`, `Nonce`, `Sign`, `Verify`.

    Examples:
      - API Functions: `BCryptGenRandom`, `CryptEncrypt`, `CryptDecrypt`.
      - Library Functions: `ring::rand`, `aes::soft::fixslice64`, `chacha20::cipher`, `hmac::lib`, `sha2::sha256`.

    - Compression: Functions or modules related to data compression or decompression. Look for terms like `Compress`, `Decompress`, `Zip`, `Unzip`, `Deflate`, `Inflate`, `Encode`, `Decode`, `Archive`, `Codec`.

    Examples:
      - API Functions: `Compress`, `Uncompress`, `deflate`, `inflate`.
      - Library Functions: `flate2::Compression`, `libflate::deflate`, `lzma::compress`, `miniz_oxide::deflate::core`.

    - String Manipulation: Functions or modules for handling, comparing, or modifying strings and text data. Look for keywords like `String`, `Str`, `wcs`, `lstrlen`, `Compare`, `Concat`, `Copy`, `Split`, `Replace`, `Format`, `Parse`, `Encode`, `Decode`, `Regex`, `Pattern`, `Utf8`, `Utf16`, `Unicode`.

    Examples:
      - API Functions: `lstrlenW`, `wcscpy`, `strcmp`, `strcat`.
      - Library Functions: `core::str::from_utf8`, `regex::builders`, `serde_json::de`, `unic_normalization::decompose`, `ahocorasick::automaton`.

    - Time-related Operations: Functions or modules for time queries, manipulation, scheduling, or delays. Look for terms like `Time`, `Date`, `Sleep`, `Wait`, `Delay`, `Timer`, `Clock`, `Instant`, `Duration`, `Schedule`, `Cron`.

    Examples:
      - API Functions: `GetSystemTime`, `Sleep`, `QueryPerformanceCounter`.
      - Library Functions: `std::time::Instant`, `chrono::DateTime`, `tokio::time::sleep`, `time::formatting`.

    - Kernel-Mode and Driver I/O: Functions or modules operating in kernel mode or facilitating direct user-mode to kernel-driver communication. Look for keywords like `Nt`, `Zw`, `Driver`, `Device`, `Kernel`, `IOCTL`, `Interrupt`, `Privilege`, `SystemCall`.

    Examples:
      - API Functions: `DeviceIoControl`, `NtOpenProcess`, `ZwCreateFile`.
      - Library Functions: `winapi::um::winnt::TOKEN_PRIVILEGES`, `kernel::syscall::ioctl::device_control`.

    - Runtime Operations: Functions or modules for error handling, dynamic library loading, function resolution, stack unwinding, logging, configuration, or other internal program management tasks that don't interact with external resources. Look for keywords like `Error`, `GetLastError`, `SetLastError`, `LoadLibrary`, `FreeLibrary`, `GetProcAddress`, `Log`, `Panic`, `Debug`, `Assert`, `Config`, `Initialize`, `Setup`.

    Examples:
      - API Functions: `GetLastError`, `LoadLibraryA`, `GetProcAddress`.
      - Library Functions: `std::panic`, `log::error`, `core::sync::atomic`, `tokio::context::runtime`, `std::once::queue`, `once_cell::sync::OnceCell`.

    - Others: Any function or module that doesn't clearly fit into the above categories based on its name.

    ---

    Additional Guidelines:

    - Focus on Function/Module Names: Categorize based solely on the name of the function or module. Do not infer functionality beyond what is suggested by the name.
    - Consider Common Prefixes/Suffixes: Be attentive to common naming patterns, such as `get_`, `set_`, `_init`, `_destroy`, which might indicate the function's purpose.
    - Language-Agnostic Approach: Function or module names may come from different programming languages or libraries (e.g., Rust, C++, Golang). Use the naming conventions and keywords common across programming languages.
    - No Prior Knowledge Assumed: If the function or module name is unfamiliar, rely on recognizable parts of the name to categorize it.
    - Ambiguous Names: If the name is too generic or doesn't match any category, assign it to 'Others'.

    """

    item_type: str = dspy.InputField(description="Type of items: 'api' or 'lib'")
    items: List[Dict[str, Any]] = dspy.InputField(description="List of items with index and name to categorize")
    categories: List[Dict[str, Any]] = dspy.InputField(description="Available category names")
    categorization: CategorizationResponse = dspy.OutputField(description="Category assignments mapping item indices to category indices")

class CategorizerModule(dspy.Module):
    """DSPy module for API/library categorization with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(CategorizerSignature)

    def forward(self, items: List[str], categories: List[str], item_type: str = "api") -> CategorizationResponse:
        """
        Categorize items using DSPy with structured inputs.

        Args:
            items: List of API/library names to categorize
            categories: List of available category names
            item_type: Type of items ("api" or "lib")

        Returns:
            CategorizationResponse Pydantic model
        """
        items_dict = [{"index": i, "name": item} for i, item in enumerate(items)]
        indexed_categories = [{"index": i, "name": category} for i, category in enumerate(categories)]

        result = self.predictor(
            item_type=item_type,
            items=items_dict,
            categories=indexed_categories,
        )
        categorization_: "CategorizationResponse" = result.categorization
        return categorization_


class MitreAttackTechnique(BaseModel):
    """Single MITRE ATT&CK technique mapping for a cluster.

    Each entry must be grounded in observable artifacts (APIs, strings,
    CAPA capabilities, call patterns) — the rationale field exists to
    force that grounding and let analysts audit the mapping.
    """

    id: str = Field(
        ...,
        description=(
            "MITRE ATT&CK Enterprise technique ID in canonical form. "
            "Use sub-technique when applicable (e.g. 'T1059.003'); otherwise the parent technique id "
            "(e.g. 'T1027'). One ID per entry; do not concatenate multiple techniques."
        ),
    )
    tactic: str = Field(
        ...,
        description=(
            "MITRE ATT&CK tactic name the technique falls under, written exactly as MITRE names it "
            "(e.g. 'Execution', 'Defense Evasion', 'Command and Control', 'Impact'). "
            "If the technique appears under multiple tactics, pick the one most aligned with the observed "
            "behavior of THIS cluster."
        ),
    )
    name: str = Field(
        ...,
        description=(
            "Human-readable technique name as MITRE publishes it (e.g. 'Windows Command Shell'). "
            "For sub-techniques include the parent name and sub-name when natural, e.g. "
            "'Command and Scripting Interpreter: Windows Command Shell'."
        ),
    )
    rationale: str = Field(
        ...,
        description=(
            "1-2 sentences (up to 3 when describing a behavioral chain) justifying the mapping. "
            "Cite the SPECIFIC artifacts or behaviors in THIS cluster that support it (e.g. "
            "'invokes cmd.exe via CreateProcessW with the /c flag observed in cluster strings'). "
            "Avoid generic restatements of the technique definition — the rationale must reference "
            "what was observed, not what the technique generally means.\n"
            "\n"
            "When the cluster's call flow shows a meaningful function-to-function sequence that "
            "grounds the technique, describe that sequence as a chain of operations in ROLE-BASED "
            "language — identify each participating function by what it does (e.g. 'a registry-"
            "read helper', 'a CreateProcessW wrapper', 'the orchestrator'), NOT by address. Raw "
            "function addresses are meaningless to report readers; describe behaviour, not "
            "identifiers. Example: 'reads `cmd.exe /c %s` from registry value "
            "`Software\\Microsoft\\Windows\\CurrentVersion\\Run` via a registry-read helper, then "
            "passes the formatted string to a CreateProcessW wrapper which executes it'. This is "
            "the strongest form of grounding when the call flow data supports it.\n"
            "\n"
            "BUT: do NOT invent chains. If no such function-to-function sequence is visible in the "
            "call flow, OR the technique is grounded by a single observable action (e.g. 'calls "
            "`vssadmin.exe Delete Shadows /all /quiet`' for T1490, or 'writes registry value `Run` "
            "under `Software\\Microsoft\\Windows\\CurrentVersion`' for T1547.001), fall back to "
            "the simpler artifact-level rationale. A fabricated chain is worse than no chain at all "
            "— if you're tempted to write 'a helper probably passes the string to a worker' "
            "without the call flow edge actually showing that hand-off, write the simpler "
            "artifact-level rationale instead.\n"
            "\n"
            "If you cannot construct a rationale grounded in this cluster's actual artifacts, OMIT "
            "the mapping rather than including a speculative one."
        ),
    )


class ClusterAnalysis(BaseModel):
    """Analysis for a single function cluster."""

    label: str = Field(
        ...,
        description=(
            "Short, descriptive label for the cluster. The label "
            "should reflect the functionality of ALL of the cluster's "
            "subclusters or referenced clusters too — not just its "
            "direct functionality. When a cluster appears to be the "
            "primary orchestrator of most or all of the binary's "
            "behavior, reflect that orchestrator role in its label."
        ),
    )
    description: str = Field(..., description="Detailed description of cluster functionality. Do NOT mention function addresses or names. The description should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters.")
    relationships: str = Field(..., description="How this cluster relates to other clusters. Always follow the format cluster.id.xxxx when referring to other clusters (Machine friendly IDs). ")
    function_prefix: str = Field(..., description="Suggested prefix for renaming functions in this cluster. Concise, descriptive, and ideally one word.")
    library_or_runtime: int = Field(default=0, description="1 if cluster is likely library/runtime code, 0 if application code")
    mitre_attack: List[MitreAttackTechnique] = Field(
        default_factory=list,
        description=(
            "MITRE ATT&CK Enterprise techniques the cluster's observed behaviors map to. "
            "ONLY include techniques actually supported by the cluster's artifacts (APIs, strings, "
            "CAPA hits, call patterns); do NOT speculate. Conversely, INCLUDE a technique when at "
            "least one concrete artifact in the cluster directly supports it. A single grounding "
            "artifact (one API call, one matching string, one CAPA hit, one distinctive command "
            "line) is sufficient — the bar is 'I can cite a specific artifact in the rationale', "
            "not 'I have multiple corroborating signals'. Under-inclusion is a real cost: a missed "
            "grounded technique disappears from the report's MITRE coverage. "
            "Empty list is valid and expected for pure utility / library / runtime clusters that "
            "don't implement adversary behavior. "
            "Order entries by tactic kill-chain position (Reconnaissance → Resource Development → "
            "Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → "
            "Credential Access → Discovery → Lateral Movement → Collection → Command and Control → "
            "Exfiltration → Impact). Within a single tactic, order by descending evidence strength "
            "(strongest-grounded mapping first)."
        ),
    )


class ClusterAnalysisItem(ClusterAnalysis):
    """Cluster analysis paired with its identifier.

    Gemini requires object properties to be explicit; representing clusters as a
    list of typed items avoids empty-property maps while the serializer preserves
    the legacy dict-of-clusters shape for downstream code.
    """

    cluster_id: str = Field(..., description="Cluster identifier as 'cluster_1'")

class BinaryCategory(enum.Enum):
    DOWNLOADER = "Downloader"
    POINT_OF_SALE = "Point-of-Sale Malware"
    RANSOMWARE = "Ransomware"
    UPLOADER = "Uploader"
    REMOTE_CONTROL_AND_ADMINISTRATION_TOOL = "Remote Control and Administration Tool"
    BACKDOOR = "Backdoor"
    FILE_INFECTOR = "File Infector"
    DROPPER = "Dropper"
    INSTALLER = "Installer"
    LAUNCHER = "Launcher"
    CONTROLLER = "Controller"
    BUILDER = "Builder"
    DISRUPTION_TOOL = "Disruption Tool"
    CREDENTIAL_STEALER = "Credential Stealer"
    PRIVILEGE_ESCALATION_TOOL = "Privilege Escalation Tool"
    REMOTE_EXPLOITATION_TOOL = "Remote Exploitation Tool"
    EXPLOIT = "Exploit"
    TUNNELER = "Tunneler"
    LATERAL_MOVEMENT_TOOL = "Lateral Movement Tool"
    RECONNAISSANCE_TOOL = "Reconnaissance Tool"
    DATA_MINER = "Data Miner"
    KEYLOGGER = "Keylogger"
    SNIFFER = "Sniffer"
    ARCHIVER = "Archiver"
    SCREEN_CAPTURE_TOOL = "Screen Capture Tool"
    DECODER = "Decoder"
    DECRYPTER = "Decrypter"
    BOOTKIT = "Bootkit"
    FRAMEWORK = "Framework"
    ROOTKIT = "Rootkit"
    CRYPTOCURRENCY_MINER = "Cryptocurrency Miner"
    SPAMBOT = "Spambot"
    ATM_MALWARE = "ATM Malware"
    UTILITY = "Utility"
    UNDETERMINED = "Undetermined"


class ClusterAnalysisResponse(BaseModel):
    """Stage-1 response — per-cluster analyses only.

    Binary-level synthesis (``binary_description``,
    ``binary_category``, ``binary_report``) is produced separately
    by :class:`BinarySynthesizerModule` from these per-cluster
    results plus aggregated raw artifacts. Splitting the two stages
    avoids re-asking the LLM for the binary-level fields on every
    batch (the prior single-stage flow generated them per batch and
    discarded all but the final batch's values) and lets stage 2
    synthesize from the whole binary in one view rather than from a
    single batch's worth of clusters.
    """

    clusters: List[ClusterAnalysisItem] = Field(..., description="List of cluster analyses with their identifiers")

    @model_validator(mode="before")
    def _coerce_legacy_clusters(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        clusters = value.get("clusters") if isinstance(value, dict) else None
        if isinstance(clusters, dict):
            value["clusters"] = [
                {"cluster_id": cid, **cdata}
                for cid, cdata in clusters.items()
            ]
        return value

    @model_serializer(mode="wrap")
    def _serialize_with_cluster_map(self, handler):
        data = handler(self)
        cluster_map = {}
        for entry in data.get("clusters", []):
            entry = dict(entry)
            cluster_id = str(entry.pop("cluster_id"))
            cluster_map[cluster_id] = entry
        data["clusters"] = cluster_map
        return data


class ClusterAnalyzerSignature(dspy.Signature):
    """
    You are analysing a binary by reading its function-cluster
    structure and per-cluster artifacts (API calls, strings,
    libraries, CAPA capabilities, and call flows). The binary may or
    may not be malicious. Describe what the artifacts actually show;
    do not presume intent.

    Per-cluster outputs (work from deepest subclusters upward):
      - `label`: short descriptive name. Reflect the functionality
        of subclusters and referenced clusters too. If a cluster
        orchestrates most of the binary, say so in the label.
      - `description`: what the cluster does. No function addresses;
        no cluster IDs (those go in `relationships`).
      - `relationships`: how this cluster interacts with referenced
        clusters. The ONLY field where `cluster.id.NNNN` may appear.
      - `function_prefix`: one-word prefix for renaming functions.
      - `library_or_runtime`: 1 for library/runtime code, 0 else.
      - `mitre_attack`: ATT&CK Enterprise mappings supported by the
        cluster's artifacts. Each entry: `id`, `tactic`, `name`,
        `rationale` (1-2 sentences citing observed artifacts). Omit
        any mapping you cannot ground; if you'd need hedging phrases
        like "may indicate" or "could suggest" or "is consistent
        with", omit instead. Empty list is correct for clusters that
        don't perform technique-shaped behaviour, and for binaries
        that don't exhibit adversary techniques regardless of class.

    This call produces PER-CLUSTER outputs only. Binary-level
    synthesis (overall description, category, and full report) is
    produced in a separate later stage by BinarySynthesizerModule
    from these per-cluster results plus aggregated raw artifacts.
    Do NOT produce binary-level fields here.
    """
    cluster_data: str = dspy.InputField(description="Raw cluster hierarchy with functions and artifacts (for reference)")
    analysis: ClusterAnalysisResponse = dspy.OutputField(description="Per-cluster analyses (label, description, relationships, function_prefix, library_or_runtime, mitre_attack) for the requested cluster subset.")



class ClusterAnalyzerModule(dspy.Module):
    """DSPy module for cluster analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(ClusterAnalyzerSignature)

    def forward(self, cluster_data: str) -> ClusterAnalysisResponse:
        """
        Analyze clusters using DSPy with structured inputs.

        Args:
            cluster_data: Formatted cluster hierarchy with functions and artifacts

        Returns:
            ClusterAnalysisResponse Pydantic model
        """

        result = self.predictor(
            cluster_data=cluster_data,
        )
        return result.analysis


class BinarySynthesisResponse(BaseModel):
    """Stage-2 response — binary-level synthesis from pre-digested
    per-cluster work plus aggregated raw artifacts.

    Produces the three binary-level outputs (``binary_description``,
    ``binary_category``, ``binary_report``) in a single dedicated
    LLM call so they are generated once, on a view of the WHOLE
    binary — not regenerated and discarded per batch as the prior
    single-stage flow did. Serializes ``binary_report`` to a
    markdown string on ``model_dump()`` so downstream consumers
    (the HTML report, the IDA cluster header, etc.) keep treating
    it as a string.
    """

    binary_description: str = Field(
        ...,
        description=(
            "Overall description of the binary's functionality. "
            "PLAIN PROSE ONLY. Absolutely no markdown formatting "
            "of any kind: no headings (`#`, `##`, `###`), no bullet "
            "lists (`-`, `*`), no asterisks for emphasis "
            "(`**bold**`, `*italic*`), no backticks for code spans "
            "(`` `code` ``), no code fences. The full description "
            "must read as natural prose. Markdown belongs in "
            "binary_report, not here. Open with 'The binary is a "
            "<morphology>...' (where <morphology> is the "
            "binary_category) with no adjectives between 'is' and "
            "the morphology: write 'The binary is a ransomware "
            "that...', NOT 'The binary is a highly structured "
            "ransomware...'. Prefer concrete claims over puffery — "
            "avoid vibes-only adjectives like 'sophisticated', "
            "'advanced', 'comprehensive', 'robust', 'complex'."
        ),
    )
    binary_category: BinaryCategory = Field(
        ...,
        description=(
            "Classification of the binary. Choose the category that "
            "matches closest based on OBSERVED ARTIFACTS, not on "
            "assumed intent.\n"
            "\n"
            "DEFAULT: if the observed artifacts do NOT clearly support "
            "a specific malicious purpose, choose 'Undetermined'. Do "
            "NOT force a binary into a malicious category to 'fill the "
            "slot' — most malware and benign software share many "
            "artifact patterns, so picking a malicious category "
            "requires evidence beyond mere artifact-pattern overlap.\n"
            "\n"
            "Categories that may legitimately describe non-malicious "
            "software in this list:\n"
            "- 'Undetermined' — benign, ambiguous, or unclassifiable.\n"
            "- 'Remote Control and Administration Tool' — EXPLICITLY "
            "  legitimate per the definition (TeamViewer, AnyDesk, "
            "  RDP clients, SSH clients).\n"
            "- 'Utility', 'Archiver', 'Sniffer', 'Cryptocurrency "
            "  Miner', 'Decoder', 'Decrypter', 'Screen Capture Tool', "
            "  'Reconnaissance Tool', 'Builder' — these definitions "
            "  are neutral; legitimate software with the same artifact "
            "  pattern exists in every one of them. Pick one only when "
            "  the artifacts clearly support that specific role.\n"
            "The remaining categories assume the binary performs "
            "adversary or malicious activity; pick one ONLY when the "
            "artifacts directly support the claim.\n"
            "\n"
            "Definitions (FLARE taxonomy):\n"
            "- Downloader: A program whose sole purpose is to download (and perhaps launch) a file from a specified address, and which does not provide any additional functionality or support any other interactive commands.\n"
            "- Point-of-Sale Malware: A program whose primary purpose is to steal financial transaction data at the point of sale (POS). Examples include malware that extracts credit card data from the memory of a POS system and malware inserted into a POS web application that steals payment information.\n"
            "- Ransomware: A program whose primary purpose is to perform some malicious action (such as encrypting data), with the goal of extracting payment from the victim in order to avoid or undo the malicious action.\n"
            "- Uploader: A program whose sole purpose is to upload a file to specified address, and which does not provide any additional functionality or support any other interactive commands.\n"
            "- Remote Control and Administration Tool: A legitimate program whose primary purpose is to remotely access and control or administer a system.\n"
            "- Backdoor: A program whose primary purpose is to allow a threat actor to interactively issue commands to the system on which it is installed.\n"
            "- File Infector: A program that inserts malicious code into a file to alter its runtime behavior.\n"
            "- Dropper: A program whose primary purpose is to extract, install and potentially launch or execute one or more files.\n"
            "- Installer: A program whose primary purpose is to install and potentially launch one or more files. Differs from a dropper in that an installer does not contain the file to be installed, but merely configures it.\n"
            "- Launcher: A program whose primary purpose is to execute an external payload or shell command. A launcher does not contain or configure a payload it executes. Examples include a program that starts an executable file located on disk and a program that reads a payload from disk and executes it in memory.\n"
            "- Controller: A program whose primary purpose is to allow a threat actor to interact with a backdoor (usually corresponds to the 'C2 server' software, but does not technically have to be a 'server').\n"
            "- Builder: A program whose primary purpose is to build (e.g., compile, create, or configure) an instance of another code family.\n"
            "- Disruption Tool: A program whose primary purpose is to damage, destroy or disable resources. Examples include DDoS utilities or disk wipers.\n"
            "- Credential Stealer: A utility whose primary purpose is to access, copy, or steal authentication credentials.\n"
            "- Privilege Escalation Tool: A program, utility, or exploit whose primary purpose is to escalate privileges on a local system (as opposed to a remote system). Excludes 'credtheft' tools which attempt to steal authentication credentials.\n"
            "- Remote Exploitation Tool: A program, utility, or exploit whose primary purpose is to gain access to a remote system. Examples include brute force utilities and self-propagating worms.\n"
            "- Exploit: A file whose sole purpose is to exploit a system (e.g. a malicious PDF).\n"
            "- Tunneler: A program that proxies or tunnels network traffic.\n"
            "- Lateral Movement Tool: A program whose primary purpose is to facilitate lateral movement within a network.\n"
            "- Reconnaissance Tool: A program whose primary purpose is to conduct some type of system or network reconnaissance (for example, enumerating accounts or systems, or conducting port scanning).\n"
            "- Data Miner: A utility whose primary purpose is to gather ('mine') data, typically for theft by threat actors. Excludes utilities that gather data such as credentials used for the purpose of escalating privileges or information used for system or network reconnaissance.\n"
            "- Keylogger: A program whose primary purpose is to capture keystrokes.\n"
            "- Sniffer: A program whose primary purpose is to capture and optionally process network traffic.\n"
            "- Archiver: A program whose primary purpose is to package one or more files into an archive, and may also extract files from an existing archive. The program may have additional options to compress or encrypt the archived files. Common examples include RAR, ZIP, and TAR.\n"
            "- Screen Capture Tool: A program whose primary purpose is to capture images or video of a system's display.\n"
            "- Decoder: A program whose primary purpose is to decode, parse, or deobfuscate an artifact(s).\n"
            "- Decrypter: A program whose primary purpose is to decrypt files or other artifacts.\n"
            "- Bootkit: A program that uses the boot process to subvert a computer before the operating system is loaded. Examples include code that modifies the MS-DOS boot sector; modifies the Windows Master Boot Record (MBR) or Volume Boot Record (VBR); or uses similar methods to modify structures associated with the Linux or MacOS operating systems.\n"
            "- Framework: A framework is a named structure around disparate capabilities aggregated to facilitate operations. Frameworks may include named capabilities borrowed from other projects. Examples include Metasploit Framework and Cobalt Strike.\n"
            "- Rootkit: A program used to hide files, processes, or other data from system information tools; can run in either user or kernel mode.\n"
            "- Cryptocurrency Miner: A program whose primary purpose is mining cryptocurrency.\n"
            "- Spambot: A program whose primary purpose is to surreptitiously send large quantities of spam e-mail. Spambots may also collect email addresses by various means including credential stuffing attacks, scanning or scraping various internet resources or guessing/brute-forcing account credentials.\n"
            "- ATM Malware: A program whose primary purpose is to manipulate ATM machines to illicitly obtain funds.\n"
            "- Utility: A program that has a specialized purpose that does not fit into any other defined category (such as keylogger, sniffer, or credential theft). Examples may include tools designed to overwrite or clear log files, encode or decode files, etc.\n"
            "- Undetermined: A program which doesn't fall in any of the above categories, OR appears to be benign."
        ),
    )
    binary_report: BinaryReport = Field(
        ...,
        description=(
            "Structured analysis report. See BinaryReport docstring for "
            "shape; serialized to a markdown string on model_dump() for "
            "downstream consumers (analyzer.generate_report_data, "
            "view.py cluster header, etc.)."
        ),
    )

    @model_serializer(mode="wrap")
    def _flatten_binary_report(self, handler):
        data = handler(self)
        if isinstance(self.binary_report, BinaryReport):
            data["binary_report"] = self.binary_report.to_markdown()
        return data


class BinarySynthesizerSignature(dspy.Signature):
    """
    You are synthesising a binary-level analysis from pre-digested
    per-cluster work plus the raw artifacts each cluster touches.
    The per-cluster labels, descriptions, relationships, and MITRE
    ATT&CK mappings have ALREADY been produced by an earlier
    analysis pass — you do NOT need to re-derive per-cluster
    meaning. Your job is the binary-level roll-up.

    The binary may or may not be malicious. Describe what the
    artifacts and per-cluster summaries actually show; do not
    presume intent.

    Input shape (provided in ``synthesis_input``):
      - A short binary header with the file format (e.g.
        "Portable executable for AMD64 (PE)") and the total
        cluster count.
      - One block per cluster containing:
          * label, description, relationships, library_or_runtime
            flag.
          * mitre_attack list (technique entries with id, tactic,
            name, rationale — already grounded per-cluster).
          * All strings, libraries, CAPA capabilities, and APIs
            attributed to that cluster's own functions.

    File format is GROUND TRUTH for runtime target. Strings,
    paths, or references in the cluster artifacts that imply
    other platforms (ESXi, Linux, macOS) are dead/inert when the
    file format doesn't match — many malware families ship per-
    platform builds from a shared codebase, so foreign-platform
    strings often persist in single-platform builds. Describe
    what THIS compilation does on its actual target, not what
    the broader family is known to do on others. Do not call a
    PE binary "multi-platform" because of ESXi strings; do not
    call an ELF binary "Windows-capable" because of registry-
    path strings. The format header is authoritative.

    Outputs:
      - `binary_description`: one paragraph, PLAIN PROSE ONLY (no
        markdown of any kind — no headings, bullets, asterisks, or
        backticks).
      - `binary_category`: one of the BinaryCategory enum values.
        See the field description for the FLARE-taxonomy
        definitions. Default to `Undetermined` when the artifacts
        do not clearly support a malicious category.
      - `binary_report`: a structured BinaryReport (overview +
        details). See the field descriptions for the rules. The
        core directive: cover EVERY observation the input
        supports — behavioural and technical alike — default to
        inclusion when grounded, quote concrete strings VERBATIM
        in backticks, and end with the observable-artifacts /
        IoC sub-section when the binary has hardcoded runtime
        identifiers.

    The per-cluster `mitre_attack` entries are your source of
    truth for technique-level grounding when writing Defense
    Evasion, Command and Control, Impact, etc. sub-sections of
    the report — reuse those rationales rather than re-deriving
    them. Cluster `description` and `relationships` fields are
    your source for cross-cluster behavioural flow.

    Example BinaryReport.details for a credential-stealer style
    binary — shows the level of depth, breadth, and verbatim-
    quotation expected; match this quality on real binaries.
    Because the example binary is explicitly malicious, the final
    sub-section uses the IoC title; for benign / ambiguous binaries
    the same content goes under `### Observable Runtime Artifacts`.

      ### Execution and Orchestration

      Initialises the runtime environment, establishes exception
      handling, and uses a mutex named `filemanager1` to enforce
      single-instance execution [c1]. Dispatches between
      credential harvesting, screen capture, and network
      exfiltration modules [c2, c4, c5].

      ### Information Stealing and Data Collection

      - **System Discovery**: retrieves computer name, current
        user, OS version, and physical memory status via
        `GetComputerNameW`, `GetUserNameW`, and
        `GlobalMemoryStatusEx` [c3].
      - **Storage Enumeration**: identifies logical drives and
        standard system folders (Desktop, AppData) to locate
        target files [c3].
      - **Application Targeting**: queries the registry for
        configuration data tied to cryptocurrency wallets
        (Bitcoin-Qt, Monero), email clients (Microsoft Outlook),
        remote-access tools (WinSCP, OpenVPN), and gaming
        platforms (Valve Steam) [c4].

      ### Screen Capture

      Captures the desktop window using GDI+ — calls `BitBlt` to
      copy the display context into a bitmap, then encodes the
      bitmap to a memory stream via `GdipSaveImageToStream` and
      stages it for exfiltration [c5].

      ### Network Communication

      Exfiltrates over HTTP using WinHttp; POSTs to
      `tastedata.shop/ag-ap.php` with a hardcoded User-Agent
      string mimicking macOS Chrome [c7].

      ### Defense Evasion

      - **DLL unhooking**: reads `ntdll.dll` directly from
        `C:\\windows\\system32\\` to bypass EDR/AV hooks [c9].
      - **Dynamic API resolution**: resolves functions at runtime
        via `LoadLibraryA` and `GetProcAddress` [c9].
      - **Memory protection**: uses `VirtualProtect` to modify
        page permissions, likely to facilitate execution of
        dynamically loaded code [c9, c11].

      ### Indicators of Compromise (IoCs)

      - **Domain**: `tastedata.shop` [c7]
      - **URL Path**: `/ag-ap.php` [c7]
      - **Mutex**: `filemanager1` [c1]
      - **User-Agent**: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` [c7]

    Real binaries vary widely in class (compression utilities,
    debuggers, installers, etc.) — pick sub-section headings that
    fit what you observed, not what this example shows.
    """
    synthesis_input: str = dspy.InputField(description="Per-cluster summaries (label, description, relationships, mitre_attack) plus all raw artifacts (strings, libraries, CAPA, APIs) per cluster, with a binary-level header.")
    synthesis: BinarySynthesisResponse = dspy.OutputField(description="Binary-level synthesis: overall description, category, and structured report.")


class BinarySynthesizerModule(dspy.Module):
    """DSPy module for stage-2 binary-level synthesis."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(BinarySynthesizerSignature)

    def forward(self, synthesis_input: str) -> BinarySynthesisResponse:
        """
        Produce the binary-level synthesis from pre-digested per-
        cluster summaries and aggregated raw artifacts.

        Args:
            synthesis_input: Formatted per-cluster summaries +
                aggregated raw artifacts, with binary-level header.

        Returns:
            BinarySynthesisResponse Pydantic model.
        """
        result = self.predictor(synthesis_input=synthesis_input)
        return result.synthesis
