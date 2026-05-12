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
            "One paragraph. MUST open with 'The binary is ' or 'This "
            "binary is '. States what the binary is and the single "
            "strongest takeaway in one or two sentences. No bullets. "
            "Code spans (`like this`) are permitted; no other markdown. "
            "Length is NOT validated — match the binary; do not pad to "
            "hit a target."
        ),
    )
    details: str = Field(
        ...,
        description=(
            "Comprehensive technical analysis as free-form markdown. "
            "Organize with `###` sub-headings driven by what THIS "
            "binary actually does — examples drawn from real reports "
            "include 'Execution and Orchestration', 'Information "
            "Stealing and Data Collection', 'Screen Capture Utility', "
            "'Network Communication and Exfiltration', 'Defense "
            "Evasion and Infrastructure', 'Privilege Escalation and "
            "Evasion', 'File Processing and Encryption Pipeline', "
            "'Reporting and User Interface'. The LLM picks the sub-"
            "headings; the schema does NOT prescribe a list. \n"
            "\n"
            "BREADTH MATTERS AS MUCH AS DEPTH. Open a SEPARATE `###` "
            "sub-section for each distinct functional area the "
            "cluster_data reveals. Do NOT consolidate unrelated "
            "behaviors into one sub-section just because they share "
            "a vague theme (e.g. do not fold privilege escalation, "
            "shadow-copy deletion, log clearing, and Safe Mode "
            "reboots into a single 'system control' sub-section — "
            "each is a distinct functional area worth its own `###`). "
            "Categories to PROBE FOR — open a sub-section about any "
            "that the artifacts support (not every binary has every "
            "category; do not invent sub-sections, but do NOT collapse "
            "supported categories into adjacent ones): \n"
            "  - Language / runtime / framework identification "
            "(Rust, Go, .NET, Python-frozen, Electron, etc. — when "
            "symbol prefixes, library names, or string patterns "
            "indicate it). \n"
            "  - Configuration handling (CLI argument parsers + "
            "verbatim flag names, config-file formats, embedded "
            "schemas, key blobs, exclusion lists). \n"
            "  - Library / framework dependencies (every notable "
            "third-party library that defines a behavior — JSON/YAML "
            "parsers, TUI/UI frameworks, HTTP clients, crypto "
            "libraries, etc.). \n"
            "  - Privilege handling (every Windows privilege token "
            "requested by name, UAC-bypass approaches, service "
            "installation, token theft). \n"
            "  - Persistence (registry run keys, scheduled tasks, "
            "services, startup folders, WMI subscriptions, "
            "boot-config edits). \n"
            "  - Defense evasion (DLL unhooking, log clearing, "
            "anti-debug, anti-VM, process hollowing, dynamic API "
            "resolution). \n"
            "  - Network discovery (each protocol / API family "
            "separately — `NetShareEnum`/`NetServerEnum` vs. ARP "
            "vs. NetBIOS vs. mDNS, etc.). \n"
            "  - Network propagation (self-spread mechanisms, "
            "`psexec.exe` with verbatim flags, remote-execution "
            "primitives, lateral-movement APIs). \n"
            "  - Network transport / C2 (HTTP/HTTPS, custom TCP/UDP "
            "protocols, DNS tunneling, hardcoded endpoints, "
            "user-agent strings). \n"
            "  - Cryptography (EVERY algorithm: AES, ChaCha20, RSA "
            "with key sizes, hash functions; EVERY mode / pattern: "
            "CBC, GCM, Full / Partial / Header / SmartPattern / "
            "DotPattern, etc.; key wrapping; nonce handling). \n"
            "  - Data collection (system discovery, registry queries, "
            "file enumeration, screen capture, keystroke logging). \n"
            "  - Process / file manipulation (process injection, "
            "file-attribute changes, ACL manipulation, shadow-copy "
            "operations). \n"
            "  - Reporting / UI / progress tracking (terminal UI "
            "libraries by name, dashboards, telemetry, logging). \n"
            "  - Indicators of Compromise (FINAL sub-section — see "
            "MANDATORY rule below). \n"
            "This list is not exhaustive; open additional `###` sub-"
            "sections for any other distinct functional area the "
            "artifacts reveal. WHEN IN DOUBT, prefer more sub-"
            "sections at finer granularity over fewer at coarser "
            "granularity. \n"
            "\n"
            "REPORT COMPREHENSIVELY AND VERBATIM. Every cluster, "
            "every interesting artifact, every behavior visible in "
            "the cluster_data MUST be mentioned somewhere in the "
            "report. Do NOT summarize away information. If the "
            "cluster_data shows 32 file extensions, list all 32. If "
            "five distinct evasion techniques, describe each. \n"
            "\n"
            "QUOTE SPECIFIC STRINGS VERBATIM. When the cluster's "
            "artifacts contain a concrete string (domain, path, "
            "registry key, mutex name, user-agent, CLI command, API "
            "or library name, file extension), write the string "
            "INSIDE BACKTICKS in the prose — do NOT paraphrase or "
            "generalize. Examples of the difference: \n"
            "  - GOOD: 'communicates with the domain `tastedata.shop`' \n"
            "  - BAD:  'communicates with a remote domain' \n"
            "  - GOOD: 'uses a mutex named `filemanager1`' \n"
            "  - BAD:  'uses a mutex' \n"
            "  - GOOD: 'queries `Software\\\\Bitcoin\\\\Bitcoin-Qt` "
            "and `Software\\\\monero-project\\\\monero-core`' \n"
            "  - BAD:  'queries registry keys for cryptocurrency "
            "wallets' \n"
            "Specific names ARE the value the analyst is reading the "
            "report to recover. Hand-waved descriptions are the "
            "regression we are explicitly trying to prevent. Hedging "
            "language ('likely', 'appears to', 'may') is fine and "
            "signals inference. \n"
            "\n"
            "MANDATORY IoC SUB-SECTION. When the cluster_data "
            "contains ANY observable indicators of compromise — "
            "concrete strings that appear in the binary's artifacts "
            "such as domains, IPs, URLs / URL paths, user-agents, "
            "mutexes, registry keys, file paths, file extensions, "
            "commands, service names, scheduled tasks, COM objects, "
            "GUIDs, or library names — you MUST include them as the "
            "FINAL sub-section under `### Indicators of Compromise "
            "(IoCs)` formatted as a bulleted list: "
            "``- **<Label>**: `<value>` ``. List ALL observed values "
            "(if there are 12 file extensions, list all 12). The "
            "framing is literal (these strings appear in the binary), "
            "not interpretive (they are known to be malicious). The "
            "IoC sub-section is omitted ONLY when the binary has no "
            "such observables at all (a pure compute / parsing "
            "utility with no network, no hardcoded paths). \n"
            "\n"
            "STYLE. Prefer concrete facts ('32 file extensions') "
            "over marketing adjectives ('comprehensive list'). The "
            "words 'sophisticated', 'advanced', 'powerful', "
            "'comprehensive', 'extensive', 'robust', 'complex', "
            "'specialized', and 'distinctive' carry no information "
            "the concrete facts can't carry better — avoid them. "
            "Cluster cross-references (the `cluster.id.NNNN` form) "
            "belong in the per-cluster `relationships` field, NOT "
            "in binary_report. \n"
            "\n"
            "Allowed markdown inside details: `###` (sub-headings, "
            "this is the only level — the top-level `##` structure is "
            "fixed by `to_markdown()`), `####` (sub-sub-headings if "
            "needed), `-` bulleted lists, `**bold**`, `` `inline "
            "code` ``. No code fences, no `##`, no tables, no images. "
            "Length is NOT validated — match the binary's substance."
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


class ArtifactAnalysisResponse(BaseModel):
    """Response model for artifact analysis."""

    interesting_indexes: List[int] = Field(..., description="List of artifact indices identified as interesting from a security perspective")


class ArtifactAnalyzerSignature(dspy.Signature):
    """
    Identify interesting artifacts from a security analysis perspective.

    You will be given artifacts organized by type (Strings, APIs, CAPA capabilities, Libraries).
    Your task is to identify which artifacts are potentially interesting from a security,
    reverse engineering, or malware analysis perspective.

    Consider artifacts interesting if they:
    - Indicate suspicious or malicious behavior
    - Reveal implementation details useful for analysis
    - Show uncommon or security-relevant functionality
    - Provide insights into the binary's purpose
    """

    artifacts: Dict[str, Dict[int, str]] = dspy.InputField(description="Artifacts organized by type (Strings, APIs, CAPA, Libraries)")
    analysis: ArtifactAnalysisResponse = dspy.OutputField(description="List of indices for artifacts deemed interesting")

class ArtifactAnalyzerModule(dspy.Module):
    """DSPy module for artifact analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(ArtifactAnalyzerSignature)

    def forward(self, artifacts: Dict[str, Dict[int, str]]) -> ArtifactAnalysisResponse:
        """
        Analyze artifacts using DSPy with structured inputs.

        Args:
            artifacts: Dict of artifacts organized by type (Strings, APIs, CAPA, Libraries)

        Returns:
            ArtifactAnalysisResponse Pydantic model
        """
        result = self.predictor(artifacts=artifacts)
        return result.analysis


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
            "1-2 sentence justification that cites the SPECIFIC artifacts or behaviors in THIS cluster "
            "that support the mapping (e.g. 'invokes cmd.exe via CreateProcessW with the /c flag observed "
            "in cluster strings'). Avoid generic restatements of the technique definition — the rationale "
            "must reference what was observed, not what the technique generally means. "
            "If you cannot construct a rationale grounded in this cluster's actual artifacts, OMIT the "
            "mapping rather than including a speculative one."
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
            "CAPA hits, call patterns); do NOT speculate. Empty list is valid and expected for "
            "pure utility / library / runtime clusters that don't implement adversary behavior. "
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
    """Response model for cluster analysis."""

    clusters: List[ClusterAnalysisItem] = Field(..., description="List of cluster analyses with their identifiers")
    binary_description: str = Field(..., description="Overall description of the binary's functionality. Plain prose only — do NOT use markdown formatting (no headings, no bullet lists, no asterisks for emphasis).")
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
        # Flatten binary_report to its rendered markdown string so the
        # rest of the codebase (analyzer.generate_report_data, the IDA
        # cluster header, the HTML report) keeps treating it as a
        # string. The structured form lives only inside the LLM/DSPy
        # boundary.
        if isinstance(self.binary_report, BinaryReport):
            data["binary_report"] = self.binary_report.to_markdown()
        return data


class ClusterAnalyzerSignature(dspy.Signature):
    """
    Analyze function clusters to understand binary functionality.

    You will be given a hierarchical structure of function clusters with
    their associated artifacts (API calls, strings, libraries, CAPA
    capabilities) and call flows.

    IMPORTANT — objectivity. The binary you are analyzing MAY OR MAY NOT
    be malicious. Your job is to describe what it does objectively,
    based solely on the observed artifacts; do NOT presume malicious
    intent. Many benign programs (compilers, archivers, installers,
    system utilities, remote-administration software, compression /
    encryption tools, antivirus products, debuggers, network
    diagnostics) share artifact patterns with malware. When the
    artifacts do not clearly indicate adversary behavior, choose
    neutral or `Undetermined` classifications over forcing the binary
    into a malicious one. Confine claims to what the artifacts
    directly support; do not infer intent.

    For each cluster, working from deepest subclusters upward, produce:
      - `label`: short descriptive name
      - `description`: what the cluster does (no function addresses,
        no cluster IDs — cluster IDs go in `relationships`). Should
        reflect the functionality of subclusters and referenced
        clusters too.
      - `relationships`: how this cluster interacts with referenced
        clusters; this is the ONLY field where `cluster.id.NNNN` form
        is allowed.
      - `function_prefix`: one-word prefix for renaming functions
      - `library_or_runtime`: 1 for library/runtime code, 0 otherwise
      - `mitre_attack`: WHEN the cluster's observed behaviors
        correspond to MITRE ATT&CK Enterprise techniques, map them.
        ONLY include techniques SUPPORTED by the cluster's actual
        artifacts (APIs, strings, CAPA hits, call patterns). Each entry
        has `id` (canonical MITRE form, sub-technique when applicable
        e.g. `T1059.003`), `tactic` (kill-chain phase, exactly as
        MITRE names it), `name`, and `rationale` (1-2 sentences citing
        specific observed artifacts/behaviors — not generic technique
        definitions). The rationale must cite what was observed in
        THIS cluster (e.g. "uses CreateProcessW with the /c cmd.exe
        pattern visible in strings"); if you can't construct such a
        rationale, OMIT the mapping. Bias STRONGLY toward omitting
        marginal mappings — a cluster with 2 well-grounded mappings is
        more useful than 8 thinly-supported ones. Use the rationale's
        own language as the test: if you'd need hedging phrases like
        "may indicate", "could suggest", "is consistent with",
        "potentially used for", "appears to be related to", or "likely
        involved in", the evidence is too weak; OMIT the mapping
        instead. Empty list is the CORRECT answer for pure utility /
        library / runtime / parsing / math / string-handling clusters
        that do not implement any technique-shaped behavior. The same
        mapping standard applies regardless of the binary's eventual
        `binary_category`: map when the artifact evidence directly
        supports the technique, omit when it doesn't. Benign software
        that genuinely performs operations matching an ATT&CK
        technique (an installer that spawns a shell, a backup tool
        that takes a shadow copy, an archiver that compresses files)
        should still get the mapping — ATT&CK is used here as a
        behavioral lens, not as a malicious/benign verdict. Order by
        ATT&CK kill-chain position; use the LATEST MITRE ATT&CK
        Enterprise matrix; if unsure of a sub-technique ID, return
        the parent technique ID rather than guessing.

    Then produce binary-level outputs:
      - `binary_description`: one-paragraph plain-prose summary (no
        markdown — that's reserved for `binary_report`).
      - `binary_category`: one of the BinaryCategory enum values.
      - `binary_report`: a BinaryReport with exactly two fields:
        `overview` (paragraph that opens with "The binary is" /
        "This binary is") and `details` (free-form markdown with
        `###` sub-headings the LLM picks based on what the binary
        actually does). The schema does NOT prescribe a list of
        sub-section names — you organize Details however the
        binary's behavior calls for. When the data contains
        observable indicators of compromise, end Details with a
        `### Indicators of Compromise (IoCs)` sub-section formatted
        as bulleted ``- **<Label>**: `<value>` `` lines. See the
        BinaryReport.overview and BinaryReport.details field
        descriptions for full guidance. LENGTH TARGETS (advisory,
        not validated): overview ≈ 200-500 chars; total rendered
        markdown ≈ 1500-4500 chars. Match the binary — a small or
        simple binary may need substantially less; a large or
        complex one may merit more. Do NOT pad to hit a target;
        do NOT truncate substantive content to fit one.

    REPORT COMPREHENSIVELY AND VERBATIM. The most common failure
    mode of earlier iterations was hand-waved descriptions that
    omitted the specific strings the analyst is reading the report
    to recover. Every cluster, every interesting artifact, every
    behavior visible in the cluster_data MUST be mentioned in
    `details`. If 32 file extensions are observed, list all 32. If
    five distinct evasion techniques, describe each. When a concrete
    string (domain, path, registry key, mutex, user-agent, API or
    library name, file extension) is in the artifacts, QUOTE IT
    VERBATIM IN BACKTICKS in the prose — do not generalize:

      - GOOD: "communicates with the domain `tastedata.shop` and
        POSTs to `/ag-ap.php`"
      - BAD:  "communicates with a remote PHP endpoint"
      - GOOD: "uses a mutex named `filemanager1`"
      - BAD:  "uses a mutex"
      - GOOD: "queries `Software\\\\Bitcoin\\\\Bitcoin-Qt` and
        `Software\\\\monero-project\\\\monero-core`"
      - BAD:  "queries cryptocurrency-wallet registry keys"

    Hedging language ('likely', 'appears to', 'may') is FINE — it
    honestly signals inference vs. direct observation, and the
    originals (origin/main, origin/gsoc_2025) use these tokens in
    their own framing. Missing information and generalized
    descriptions are the worst failure modes.

    BREADTH MATTERS AS MUCH AS DEPTH. Open a SEPARATE `###` sub-
    section for each distinct functional area the cluster_data
    reveals; do NOT consolidate unrelated behaviors into one sub-
    section just because they share a vague theme. Categories to
    probe for (open a sub-section about any the artifacts support;
    not every binary has every one): language/runtime identification;
    CLI / configuration handling; library and framework dependencies;
    privilege handling (every token by name); persistence mechanisms;
    defense evasion; network discovery (each protocol family
    separately); network propagation; network transport / C2;
    cryptography (every algorithm + mode); data collection; process /
    file manipulation; reporting / UI / progress tracking; IoCs.
    See BinaryReport.details for the full checklist. WHEN IN DOUBT,
    prefer more sub-sections at finer granularity over fewer at
    coarser granularity.

    MANDATORY IoC SUB-SECTION. When the cluster_data contains ANY
    domains, IPs, URLs, user-agents, mutexes, registry keys, file
    paths, file extensions, commands, service names, scheduled
    tasks, COM objects, GUIDs, or library names that the binary
    references as runtime observables, the LAST sub-section of
    `details` MUST be `### Indicators of Compromise (IoCs)` listing
    every one, formatted as ``- **<Label>**: `<value>` ``. Omit
    the IoC sub-section ONLY when the binary has no such
    observables at all.

    Evidence basis: your input is the artifacts (strings, APIs,
    libraries, CAPA matches) and call flows shown above — NOT the
    binary's source code. Confine claims in `binary_report` (and in
    `mitre_attack` rationales) to what those artifacts directly
    support. You can use hedges to mark inference, but you should
    not state observations the artifacts don't contain.
      - GOOD: "Captures the desktop using GDI handles and stages
        the bitmap in a memory buffer."
      - GOOD: "Likely facilitates execution of dynamically loaded
        code by adjusting page protections."  (hedge marks inference)
      - BAD  (marketing adjectives + filler instead of facts):
        "Uses a sophisticated screen-capture technique for
        comprehensive surveillance." Replace with concrete facts.
      - BAD  (presumes malice without artifact support):
        "Compresses files for exfiltration to attacker-controlled
        servers." — the "exfiltration" claim names a network
        destination the artifacts do not show. If the cluster
        compresses files and there is no observed network call,
        describe only the compression.

    Avoid the banned-token list (marketing adjectives like
    'sophisticated' / 'advanced' / 'robust' / 'comprehensive' /
    'extensive', and the substring 'cluster.id.'). Use concrete
    numbers and concrete artifact names — '32 file extensions',
    not 'comprehensive list'.

    Worked example #1 — a BinaryReport for a credential-stealer
    style binary. Demonstrates the rich, comprehensive style and
    the IoC sub-section format:

      overview: "The binary is a credential stealer that
        systematically harvests environment information, captures
        user activity via screenshots, and pulls credentials from
        installed applications, exfiltrating the results to a
        remote HTTP server. It uses standard Windows APIs for data
        collection and the WinHttp library for exfiltration."

      details: |
        ### Execution and Orchestration

        The binary's execution begins with an orchestration layer
        that initialises the environment and manages the transition
        between primary modules. It establishes exception handling
        routines and uses a mutex named `filemanager1` to ensure
        only a single instance runs on the host.

        ### Information Stealing and Data Collection

        The core functionality lives in a dedicated data-collection
        engine that performs:

        - **System Discovery**: Retrieves the computer name,
          current username, OS version, and physical memory status
          via `GetComputerNameW`, `GetUserNameW`, and
          `GlobalMemoryStatusEx`.
        - **Storage and Environment Enumeration**: Identifies all
          logical drives and maps standard system folders (Desktop,
          AppData) to locate target files.
        - **Application Targeting**: Searches the registry for
          configuration data tied to high-value applications:
          - Cryptocurrency Wallets: Bitcoin-Qt, Monero core wallets
          - Communication: Microsoft Outlook profiles
          - Remote Access: WinSCP sessions, OpenVPN configurations
          - Gaming: Valve Steam account information

        ### Screen Capture Utility

        A specialised module leverages the GDI+ library to capture
        the desktop window. It uses `BitBlt` to copy the display
        context into a bitmap, which is then encoded and saved to
        a stream for exfiltration.

        ### Network Communication and Exfiltration

        Exfiltration runs over HTTP via the WinHttp library. The
        malware communicates with the domain `tastedata.shop`,
        POSTing collected data to the PHP endpoint `/ag-ap.php`.
        Requests use a hardcoded User-Agent string mimicking a
        macOS Chrome browser.

        ### Defense Evasion and Infrastructure

        Several defensive behaviours are present:

        - **DLL Unhooking**: Reads `ntdll.dll` directly from
          `C:\\windows\\system32\\` — a common technique to bypass
          EDR/AV hooks by loading a clean library copy.
        - **Dynamic API Resolution**: Resolves critical functions
          at runtime via `LoadLibraryA` and `GetProcAddress`,
          hindering static analysis.
        - **Memory Protection**: Uses `VirtualProtect` to modify
          memory-page permissions, likely to facilitate execution
          of dynamically loaded code or protect sensitive buffers.

        ### Indicators of Compromise (IoCs)

        - **Domain**: `tastedata.shop`
        - **URL Path**: `/ag-ap.php`
        - **Mutex**: `filemanager1`
        - **User-Agent**: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`

    Worked example #2 — a BinaryReport for a benign binary (a
    small CRC32 command-line utility). Demonstrates that the same
    schema accommodates a terse binary — there are no IoCs, the
    details body is short, and `binary_category` is `Utility` or
    `Undetermined`, NOT a malicious category. Match the binary's
    actual substance.

      overview: "The binary is a command-line CRC32 utility that
        reads input bytes (from stdin or from a path supplied as
        an argument), computes the CRC32 checksum, and prints the
        result. It performs no network I/O, registry access, or
        process spawning."

      details: |
        ### CRC32 Computation Pipeline

        Reads input bytes either from stdin or from the file path
        supplied as the first argument. Computes the CRC32
        checksum using a precomputed table-based reflection of the
        IEEE 802.3 polynomial. Prints the result in lowercase hex.

        ### Command-line Argument Handling

        Accepts a single optional positional argument: a file path
        to checksum. With no argument, reads bytes from stdin
        until EOF. Errors during file open are reported to stderr
        and the process exits with a non-zero status.
    """
    cluster_data: str = dspy.InputField(description="Raw cluster hierarchy with functions and artifacts (for reference)")
    analysis: ClusterAnalysisResponse = dspy.OutputField(description="Complete cluster analysis with per-cluster metadata and binary-level insights")

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
