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

CLUSTER_ANALYZER_PROMPT = """You are a malware analyst examining a binary. 
You will analyze clusters of functions containing suspicious behaviors.
Each cluster shows functions, their artifacts (APIs and their corresponding calls (if available), strings, library names, CAPA static analysis tool results etc.), and call relationships.

Here's the cluster data formatted hierarchically:

{cluster_data}

Please analyze each cluster (starting with the deepest subclusters and working up) and provide:
1. Label: A short name indicating the cluster's functionality. 
    a. The label should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters. 
    b. Try and identify the main orchestrator cluster of most if not all functionality of the binary and reflect that in the corresponding label as well (where applicable).
2. Description: Short summary of what the cluster appears to do. Do NOT mention function addresses or names.
    a. The description should not just be reflective of the cluster's own functionality, but also of the functionality of ALL of it's subclusters or referenced clusters. 
3. Relationships: How it interacts with referenced clusters (if applicable). Defer mentioning specific cluster IDs (cluster.id.xxxx) to this instead of Description. Do NOT mention function addresses or names.
4. Function Prefix: A one word prefix that can be added to the functions of this cluster, and that captures the functionality of this cluster as best possible.

After analyzing all clusters, please provide:
4. Provide an overall description of the binary based on your analysis on the above point
5. Choose a category for the binary that matches closest to one of the following listed below.
6. A report with general formatting (not markdown) that includes as much detail as available about all of the malware's capabilities and provides an extensive overview of how it functions. 
    a. This report should be objective, should not assume anything, only state facts and use technical terminology where applicable. 
    b. If any list of items (functionalities, commands, paths etc) is to be mentioned, the full list should be provided and nothing should be left out. 
    c. This report should NOT have mentions of cluster IDs.
    d. This report should NOT mention APIs or syscalls by name while describing functionality.
    e. This report should include any relevant and unique IoCs (Indicatos of Compromise) such as file paths, URLs, domains, IPs/ports, commands executed, registry keys/values and COM objects.
    f. This report should explicitly include any persistence mechanisms, if discovered.

Downloader:	A program whose sole purpose is to download (and perhaps launch) a file from a specified address, and which does not provide any additional functionality or support any other interactive commands.
Point-of-Sale Malware:	A program whose primary purpose is to steal financial transaction data at the point of sale (POS). Examples include malware that extracts credit card data from the memory of a POS system and malware inserted into a POS web application that steals payment information.
Ransomware:	A program whose primary purpose is to perform some malicious action (such as encrypting data), with the goal of extracting payment from the victim in order to avoid or undo the malicious action.
Uploader:	A program whose sole purpose is to upload a file to specified address, and which does not provide any additional functionality or support any other interactive commands.
Remote Control and Administration Tool:	A legitimate program whose primary purpose is to remotely access and control or administer a system.
Lightweight Backdoor:.toehold	A backdoor program that allows an attacker to establish limited control over a victim host. Can be considered a "lightweight" backdoor; interactive functionality is limited to a commands such as sleep, file transfer, and / or command shell.
Backdoor - Webshell:.webshell	A backdoor that depends on being deployed on a web server and is controlled via a web protocol.
Backdoor - Botnet:.botnet	A backdoor that allows a threat actor to issue interactive commands, but also has the capability to network with its peers, either directly or via a central or intermediate controller, typically for the purpose of controlling large numbers of backdoors (or compromised systems) at once.
Backdoor:	A program whose primary purpose is to allow a threat actor to interactively issue commands to the system on which it is installed.
File Infector:	A program that inserts malicious code into a file to alter its runtime behavior.
Dropper:.memonly	A dropper that loads its payload directly into memory; the payload is never written to disk.
Dropper:	A program whose primary purpose is to extract, install and potentially launch or execute one or more files.
Installer:	A program whose primary purpose is to install and potentially launch one or more files. Differs from a dropper in that an installer does not contain the file to be installed, but merely configures it.
Launcher:	A program whose primary purpose is to execute an external payload or shell command. A launcher does not contain or configure a payload it executes. Examples include a program that starts an executable file located on disk and a program that reads a payload from disk and executes it in memory.
Controller:	A program whose primary purpose is to allow a threat actor to interact with a backdoor (usually corresponds to the "C2 server" software, but does not technically have to be a "server").
Exploit Builder:.exploit	A program whose primary purpose is to wrap malicious exploit code inside another file such as a document, spreadsheet, powerpoint or pdf file. When opened, the file attempts to exploit a vulnerability and if successful, the exploit code is executed. The final payload may be downloaded or dropped directly after exploitation.
Builder:	A program whose primary purpose is to build (e.g., compile, create, or configure) an instance of another code family.
Disruption Tool:	A program whose primary purpose is to damage, destroy or disable resources. Examples include DDoS utilities or disk wipers.
Credential Stealer:	A utility whose primary purpose is to access, copy, or steal authentication credentials.
Privilege Escalation Tool:	A program, utility, or exploit whose primary purpose is to escalate privileges on a local system (as opposed to a remote system). Excludes 'credtheft' tools which attempt to steal authentication credentials.
Remote Exploitation Tool:	A program, utility, or exploit whose primary purpose is to gain access to a remote system. Examples include brute force utilities and self-propagating worms.
Exploit:	A file whose sole purpose is to exploit a system (e.g. a malicious PDF)
Tunneler:	A program that proxies or tunnels network traffic.
Lateral Movement Tool:	A program whose primary purpose is to facilitate lateral movement within a network.
Reconnaissance Tool:	A program whose primary purpose is to conduct some type of system or network reconnaissance (for example, enumerating accounts or systems, or conducting port scanning).
Data Miner:	A utility whose primary purpose is to gather ('mine') data, typically for theft by threat actors. Excludes utilities that gather data such as credentials used for the purpose of escalating privileges or information used for system or network reconnaissance.
Keylogger:	A program whose primary purpose is to capture keystrokes.
Sniffer:	A program whose primary purpose is to capture and optionally process network traffic.
Archiver:	A program whose primary purpose is to package one or more files into an archive, and may also extract files from an existing archive. The program may have additional options to compress or encrypt the archived files. Common examples include RAR, ZIP, and TAR.
Screen Capture Tool:	A program whose primary purpose is to capture images or video of a system's display.
Decoder:	A program whose primary purpose is to decode, parse, or deobfuscate an artifact(s).
Decrypter:	A program whose primary purpose is to decrypt files or other artifacts.
Bootkit:	A program that uses the boot process to subvert a computer before the operating system is loaded. Examples include code that modifies the MS-DOS boot sector; modifies the Windows Master Boot Record (MBR) or Volume Boot Record (VBR); or uses similar methods to modify structures associated with the Linux or MacOS operating systems.
Framework:	A framework is named structure around disparate capabilities aggregated to facilitate operations. Frameworks may include named capabilities borrowed from other projects. Examples include Metasploit Framework and Cobalt Strike.
Rootkit:	A program used to hide files, processes, or other data from system information tools; can run in either user or kernel mode.
Cryptocurrency Miner:	A program whose primary purpose is mining cryptocurrency.
Spambot:	A program whose primary purpose is to to surreptitiously send large quantities of spam e-mail. Spambots may also collect email addresses by various means including credential stuffing attacks, scanning or scraping various internet resources or guessing/brute-forcing account credentials.
ATM Malware:	A program whose primary purpose is to manipulate ATM machines to illicitly obtain funds.
Utility:	A program that has a specialized purpose that does not fit into any other defined category (such as keylogger, sniffer, or credential theft). Examples may include tools designed to overwrite or clear log files, encode or decode files, etc.
Undetermined: A program which doesn't fall in any of the above categories, OR appears to be benign.

Format your response as a JSON object that includes the cluster analyses (with cluster IDs as keys) under a "clusters" parent key, along with the binary description and category. Is it IMPORTANT that when referring to other clusters in relationships, use formatting like cluster.id.xxxx such that if you're refering to cluster 1 it would read as cluster.id.0001. Following is an example of the expected JSON object:
{
    "clusters": {
        "cluster_12": {
            "label": "Network Communication Module",
            "description": "Implements custom protocol for C2 communication",
            "relationships": "Provides encrypted channel used by cluster.id.0067",
            "function_prefix:" "netmod"
        },
        "cluster_67": {
            "label": "Command Execution Module",
            "description": "Executes commands received from the network",
            "relationships": "Uses communication channel from cluster.id.0012",
            "function_prefix:" "cmd"
        }
    },
    "binary_category": "Backdoor",
    "binary_description": "This binary is a backdoor that allows remote command execution via a custom encrypted protocol.",
    "binary_report": "The malware is a Backdoor that can connect to it's C2 (command and control) server over a custom protocol. The malware has the capability to...
}

Focus on:
- Technical behaviors revealed by artifacts
- How functions work together within each cluster
- How clusters build upon each other's functionality
- Common malware patterns and techniques

Ensure descriptions are clear and precise. Use technical terms where appropriate. Return only the JSON and do not include any explanatory text. Do NOT wrap the JSON in code fences or formatting.
All the required keys should be present in all respective JSON values. Even if a cluster does not have relevant data for a particular field, you should still include the key. For example: "relationships": "None".
Do not use backslashes, string quotes or new lines in the binary_report.
"""
