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

from typing import Any, Dict, List
import enum

import dspy
from pydantic import BaseModel, Field

class CategorizationResponse(BaseModel):
    """Response model for API/Library categorization."""

    category_assignments: Dict[str, int] = Field(..., description="Mapping of item index (as string) to category index (0-based)")

    class Config:
        json_schema_extra = {
            "example": {
                "category_assignments": {
                    "0": 0,
                    "1": 2,
                    "2": 5
                }
            }
        }

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

    class Config:
        json_schema_extra = {
            "example": {
                "interesting_indexes": [0, 3, 7, 12]
            }
        }


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


class ClusterAnalysis(BaseModel):
    """Analysis for a single function cluster."""

    label: str = Field(..., description="Short, descriptive label for the cluster")
    description: str = Field(..., description="Detailed description of cluster functionality. Do NOT mention function addresses or names. The description should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters.")
    relationships: str = Field(..., description="How this cluster relates to other clusters")
    function_prefix: str = Field(..., description="Suggested prefix for renaming functions in this cluster")
    library_or_runtime: int = Field(default=0, description="1 if cluster is likely library/runtime code, 0 if application code")

    class Config:
        json_schema_extra = {
            "example": {
                "label": "Network Communication",
                "description": "Handles HTTP requests and socket operations",
                "relationships": "Called by authentication cluster, uses crypto cluster",
                "function_prefix": "net_",
                "library_or_runtime": 0
            }
        }

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

    clusters: Dict[str, ClusterAnalysis] = Field(..., description="Mapping of cluster_id to ClusterAnalysis")
    binary_description: str = Field(..., description="Overall description of the binary's functionality")
    binary_category: BinaryCategory = Field(..., description="Classification of the binary")
    binary_report: str = Field(default="", description="Detailed analysis report for the binary")

    class Config:
        json_schema_extra = {
            "example": {
                "clusters": {
                    "cluster_1": {
                        "label": "Initialization",
                        "description": "Sets up application state",
                        "relationships": "Called first, initializes all other clusters",
                        "function_prefix": "init_",
                        "library_or_runtime": 0
                    }
                },
                "binary_description": "Network monitoring tool with logging capabilities",
                "binary_category": "Utility",
                "binary_report": "Detailed analysis shows..."
            }
        }

class ClusterAnalyzerSignature(dspy.Signature):
    """
    Analyze function clusters to understand binary functionality.

    You will be given a hierarchical structure of function clusters with their associated
    artifacts (API calls, strings, CAPA capabilities) and call flows.

    Your task is to:
    Analyze each cluster (starting with the deepest subclusters and working up) and:
    1. Provide a descriptive label for each cluster
    2. Explain what each cluster does based on its functions and artifacts
    3. Describe how clusters relate to each other
    4. Suggest a function naming prefix for renaming
    5. Identify if the cluster is likely library/runtime code
    6. Provide an overall binary description and category
    7. Generate a comprehensive analysis report

    This report should be objective, should not assume anything, only state facts and use technical terminology where applicable.

    Focus on:
    - Technical behaviors revealed by artifacts
    - How functions work together within each cluster
    - How clusters build upon each other's functionality
    - Common malware patterns and techniques
    """
    # """
    # You are a malware analyst examining a binary.
    # You will analyze clusters of functions containing suspicious behaviors.
    # Each cluster shows functions, their artifacts (APIs and their corresponding calls (if available), strings, library names, CAPA static analysis tool results etc.), and call relationships.

    # Please analyze each cluster (starting with the deepest subclusters and working up) and provide:
    # 1. Label: A short name indicating the cluster's functionality.
    #     a. The label should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters.
    #     b. Try and identify the main orchestrator cluster of most if not all functionality of the binary and reflect that in the corresponding label as well (where applicable).
    # 2. Description: Short summary of what the cluster appears to do. Do NOT mention function addresses or names.
    #     a. The description should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters.
    # 3. Relationships: How it interacts with referenced clusters (if applicable). Defer mentioning specific cluster IDs (cluster.id.xxxx) to this instead of Description. Do NOT mention function addresses or names.
    # 4. Function Prefix: A one word prefix that can be added to the functions of this cluster, and that captures the functionality of this cluster as best possible.

    # After analyzing all clusters, please provide:
    # 4. Provide an overall description of the binary based on your analysis on the above point
    # 6. A report with general formatting (not markdown) that includes as much detail as available about all of the malware's capabilities and provides an extensive overview of how it functions.
    #     a. This report should be objective, should not assume anything, only state facts and use technical terminology where applicable.
    #     b. If any list of items (functionalities, commands, paths etc) is to be mentioned, the full list should be provided and nothing should be left out.
    #     c. This report should NOT have mentions of cluster IDs.
    #     d. This report should NOT mention APIs or syscalls by name while describing functionality.
    #     e. This report should include any relevant and unique IoCs (Indicatos of Compromise) such as file paths, URLs, domains, IPs/ports, commands executed, registry keys/values and COM objects.
    #     f. This report should explicitly include any persistence mechanisms, if discovered.

    # Focus on:
    # - Technical behaviors revealed by artifacts
    # - How functions work together within each cluster
    # - How clusters build upon each other's functionality
    # - Common malware patterns and techniques
    # """
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
