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

ARTIFACT_ANALYZER_PROMPT = """
You will be provided with a JSON object containing artifacts extracted from a binary file. The artifacts are organized by type, where each type maps to a dictionary of artifacts. Each artifact is represented by an `index` and its `content`.

**Input Format:**

```json
{
  "type1": {
    "index1": "artifact1",
    "index2": "artifact2",
    ...
  },
  "type2": {
    "index3": "artifact3",
    "index4": "artifact4",
    ...
  },
  ...
}
```

**Your Task:**

Analyze the provided artifacts and return a JSON object containing only the indexes of the "interesting" artifacts according to the criteria specified below.

Criteria for "Interesting" Artifacts:
APIs

    Include APIs that:
        Indicate potential malware functionality or significant operations.
        Are used for file operations, network communications, process and thread manipulation, registry operations, memory management, cryptography, anti-debugging, or other functions relevant to malware behavior.

    Examples to Include:
        File Operations:
            CreateFileW, DeleteFileW, ReadFile, WriteFile, CopyFile, MoveFile, SetFileAttributesW
        Network Communications:
            WSAStartup, socket, connect, send, recv, getaddrinfo, bind, closesocket
        Process and Thread Manipulation:
            CreateProcessW, CreateThread, TerminateProcess, OpenProcess, SuspendThread, ResumeThread, VirtualAllocEx, WriteProcessMemory, ReadProcessMemory
        Registry Operations:
            RegOpenKeyExW, RegSetValueExW, RegCreateKeyExW, RegDeleteKeyW, RegQueryValueExW
        Memory Management:
            VirtualAlloc, VirtualProtect, VirtualProtectEx, HeapCreate, HeapAlloc, HeapReAlloc, HeapFree
        Cryptography:
            CryptEncrypt, CryptDecrypt, CryptAcquireContext, CryptHashData, CryptGenKey
        Anti-Debugging/Anti-Analysis:
            IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, OutputDebugString, SetUnhandledExceptionFilter
        System Information and Control:
            GetVersionEx, GetSystemInfo, SystemParametersInfoW (when used to change settings like wallpaper), AdjustTokenPrivileges

    Exclude APIs that:
        Are standard runtime functions, basic memory allocation, or common string manipulation from standard libraries, unless they have specific relevance to malware functionality.

    Examples to Exclude:
        Standard C Runtime Functions:
            malloc, free, memcpy, memset, strcpy, strcat, strlen, sprintf, printf
        Basic Synchronization Functions:
            InitializeCriticalSection, EnterCriticalSection, LeaveCriticalSection (unless used in a malicious context)
        Common Error Handling and Utility Functions:
            GetLastError, SetLastError, Sleep, ExitProcess (unless they are part of a malicious operation)
        Exception Handling and Vectored Exception Handling:
            RaiseException, AddVectoredExceptionHandler, UnhandledExceptionFilter

Libraries

    Include Libraries and Library References that:
        Are part of the binary's own codebase or custom libraries developed by the malware author.
        Hint at interesting functionality or specific capabilities used by the malware.
        Indicate usage of specific functionalities like cryptography, networking, compression, or other operations relevant to the malware's behavior.
        Important: Include all library references except those explicitly identified as standard or common libraries.

    Examples to Include:
        Custom Cryptographic Libraries:
            aes::soft::fixslice32
            chacha20::chacha
            rsa::pkcs1v15
            cipher::stream
            ctr::lib
            encryptappparams::src::lib
            encryptlib::src::app
        Networking Libraries:
            std::net::ip
            std::net::addr
            std::net::parser
        Compression Libraries:
            deflate::compress
            libflate::deflate::symbol
            minizoxide::deflate::stream
            cryptoflate::src::lib
        User Interface Components:
            tui::terminal
            crossterm::command
            tui::widgets::list
            locker::core::renderer
        Custom Modules or Functions:
            locker::core::stack
            locker::pipeline::filework
            locker::core::os::windows::console
            locker::core::soft_persistence
            locker::core::env
            locker::core::config
            encrypt_lib::windows

    Exclude Libraries that:
        Are standard libraries or parts of common language runtimes that do not provide meaningful insights into the malware's functionality.
        Belong to standard library components, common data structures, or general-purpose utilities not specific to the malware.

    Examples to Exclude:
        Standard Library Components (e.g., parts of the Rust standard library):
            alloc::btree::navigate
            alloc::map::entry
            alloc::vec::mod
            core::fmt::mod
            core::slice::iter
            core::str::pattern
            std::io::mod
            std::thread::mod
            std::sync::once

    Note:
        Include all other library references, especially those that may not be standard or may hint at custom functionality, even if they are not explicitly listed in the examples to include.
        When in doubt, prefer including the library reference unless it is clearly a standard library component as per the examples to exclude.

CAPA

    Include CAPA Results that:
        Indicate suspicious activities or known malicious capabilities.
        Highlight behaviors commonly associated with malware.

    Examples to Include:
        File System Manipulation:
            host-interaction/file-system, delete directory
            host-interaction/file-system, move file
            host-interaction/file-system, delete file
            impact/inhibit-system-recovery, delete volume shadow copies
        Process and Thread Manipulation:
            host-interaction/process, terminate process
            host-interaction/process, create process with modified I/O handles and window
            host-interaction/process, allocate or change RWX memory
        User and System Operations:
            host-interaction/user, impersonate user
            host-interaction/os, shutdown system
            host-interaction/uac, bypass UAC via ICMLuaUtil
        Network Activity:
            communication, send data
            communication/socket, send data on socket
            communication/dns, resolve DNS
        Cryptography and Encryption:
            data-manipulation/encryption, encrypt data using AES via x86 extensions
            data-manipulation/encryption, encrypt data using RC4 PRGA
            data-manipulation/encryption, encrypt data using Salsa20 or ChaCha
        Anti-Debugging/Anti-Analysis:
            anti-analysis/anti-forensic, patch process command line
            anti-analysis/obfuscation, contain obfuscated stackstrings

    Exclude CAPA Results that:
        Represent common operations in legitimate software and do not indicate malicious behavior.

    Examples to Exclude:
        Common Operations:
            query environment variable
            allocate thread local storage
            get system time
            read file, write file (unless in a suspicious context)
        Generic Network Operations:
            initialize Winsock library (unless used maliciously)
        Standard Process Operations:
            create thread (unless used in code injection or similar malicious activity)
        Memory Allocation:
            allocate memory, free memory

Strings

    Include Strings that:
        Are written by the malware author as part of the user code.
        Reveal functionality, operations, error messages, internal processes, or any text indicating malicious operations.
        Contain function names, module names, internal code references, file paths, registry keys, system commands, error messages, network addresses, or operational messages.
        Important: Include all strings except those explicitly identified as standard library messages or common runtime errors or are garbage/gibberish.

    Examples to Include:
        Operational Messages:
            "Failed to spawn thread"
            "Invalid access token."
            "Cannot access a Thread Local Storage value during"
            "Safemode Reboot Callback!"
            "Preparing Logger"
            "Init Globals"
            "Starting Supervisor"
            "Starting File Processing Pipeline"
        Function and Module References:
            "encrypt_lib::windows"
            "locker::core::renderer"
            "locker::core::stack"
            "encryptappparams::src::lib"
        Malicious Indicators:
            "Trying to remove shadow copies"
            "Cleaning event log"
            "Shutdown Routine"
            "Dropping Note and Wallpaper Image"
            "Clustering disabled - Network Down"
        File Paths and Registry Keys:
            "C:\\liyareraxu-moropiciheki\\wufevuvusi\\83\\yimuciz.pdb"
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control"
            "set_desktop_image"
        System Commands and Scripts:
            "reg add"
            "reg delete"
            "sc delete"
            "attach="
            "set_desktop_image::set_desktop_wallpaper="
        Network Addresses:
            "127.0.0.1:"
        Others:
            Any string that provides insight into the malware's behavior or intentions.

    Exclude Strings that:
        Are standard error messages, debug messages, or compiler-generated messages from standard libraries.
        Are generic error messages or status messages commonly found in standard libraries or language runtimes.
        Do not contribute to understanding the malware's unique functionality. Additionaly, exclude strings 
        containing only whitespace and/or junk characters or in general a gibberish combination of characters.

    Examples to Exclude:
        Standard Library Messages and Errors:
            "Error:"
            "Unknown error"
            "Write error"
            "OS Error"
            "LayoutError"
            "ParseIntError"
            "Utf8Errorvalid_up_toerror_len"
            "SystemTimeError"
            "FromUtf8Errorbytes"
            "assertion failed: !buf.is_empty()"
            "already mutably borrowed"
            "BorrowErrorBorrowMutError"
        Strings Indicating Standard Library Components:
            "alloc::vec::mod"
            "core::str::pattern"
            "core::fmt::mod"
            "std::io::mod"
            "alloc::btree::node"
            "core::slice::sort"

    Note:
        Include all other strings, especially those that may provide insight into the malware's behavior, even if they are not explicitly listed in the examples to include.
        When in doubt, prefer including the string unless it is clearly a standard library message or error as per the examples to exclude.


**Output Format:**

Your response must be a pure JSON object with the following structure:

```
{
  "interesting_indexes": [index1, index2, index3, ...]
}
```

The interesting_indexes key maps to an array of integers (indexes) representing the selected "interesting" artifacts.
Do not include any additional text, explanations, or formatting outside of the JSON object.
Ensure that the JSON is correctly formatted and can be parsed without errors.


**Example Input:**

```
{
  "Strings": {
    "1": "Initialization complete.",
    "3": "C:\\sdfsssdf-sdfdssdf\\sfsdfdsdf\\91\\fsdfdf.pdb",
    "6": "/usr/local/lib/libc.so"
  },
  "APIs": {
    "2": "kernel32.dll:CreateFileW",
    "5": "msvcrt.dll:memcpy"
  },
  "CAPA": {
    "4": "Create remote thread in another process",
    "7": "Bind to a socket to receive incoming connections"
  },
  "Libraries": {
    "8": "openssl.dll"
  }
}
```

**Example Output:**

```
{
  "interesting_indexes": [2, 3, 4, 7]
}
```

Instructions:

    1) Analyze Each Artifact:
        a) For each type, examine the artifacts in the provided dictionaries.
        b) Use the content to determine if the artifact meets the criteria for being "interesting".

    2) Select "Interesting" Artifacts:
        a) If an artifact is deemed "interesting," include its index in the output array.
        b) Do not include artifacts that do not meet the criteria.

    3) Prepare the Output:
        a) Create a JSON object with the key interesting_indexes.
        b) The value should be an array of integers representing the indexes of the selected artifacts.
        c) Do not include any other keys or data in the JSON.

    4) Ensure Correct JSON Formatting:
        a) The output must be valid JSON.
        b) Do not include extra commas, missing brackets, or any syntax errors.

Remember:

    1) Only include the indexes of artifacts that are "interesting" according to the criteria.
    2) Exclude all artifacts that do not meet the criteria.
    3) Your output should be concise and strictly follow the specified format.
    4) If you are unsure about whether to include or exclude something, then just include it.
    5) Be less restrictive in what you include.


Begin analyzing the artifacts and provide raw JSON output without quotes or code snippets. Do NOT wrap the JSON in code fences or formatting. The input is as follows:
"""
