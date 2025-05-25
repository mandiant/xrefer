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

CATEGORIZER_PROMPT = """
Categorize the following {{TYPE}}s according to their most basic and direct functionality. Use ONLY the categories in the provided list. If an item doesn't clearly fit into the main categories, assign it to the 'Others' category. Base your decision solely on the function or library item name, focusing on recognizable patterns, prefixes, and keywords, without making assumptions about higher-level behaviors or implementations. The names may come from any programming language or library, and can be arbitrary.

Categories:
{{CATEGORIES}}

Guidelines for categorization (do not include in response):

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

---

Items to categorize are provided below, with each item having an index. Your task is to return the categorization result as a JSON object containing only the item indexes and their corresponding category indexes (category position in the provided category list, 0-based).

Input format:
[
  {"index": 0, "name": "CreateFileW"},
  {"index": 1, "name": "awsconfig::fsutil"},
  {"index": 2, "name": "std::thread::spawn"},
  ...
]

Output format:
{
  "category_assignments": {
    "0": 0,    // category index for item index 0
    "1": 0,    // category index for item index 1
    "2": 3,    // category index for item index 2
    ...
  }
}

Return only the JSON and do not include any explanatory text. Do not wrap the JSON in code fences or formatting. Ensure all items are assigned a category index. Do not miss any item.

{{ITEMS}}
"""
