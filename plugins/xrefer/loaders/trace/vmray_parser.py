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

import collections
import io
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from zipfile import BadZipfile, ZipFile

from xrefer.core.helpers import log
from xrefer.loaders.trace.base import BaseTraceParser


class VMRayTraceParser(BaseTraceParser):
    """
    Parser for VMRay XML API traces from a password-protected analysis ZIP.

    This parser:
    - Opens the given zip archive (password: 'infected'),
    - Extracts logs/flog.xml and logs/summary_v2.json,
    - Correlates memory regions, file paths, and file hashes to identify
      the memory region containing the sample specified by `self.sample_sha256`.
    - Determines `image_base` from the identified region if `self.image_base` is not already set.
    - If the identified region’s start address does not match `image_base`, it computes a delta
      and applies that delta to all API call addresses for the corresponding process, ensuring
      perfect alignment with the primary sample in IDA Pro.
    """

    def __init__(self, backend=None):
        super().__init__(backend)
        self.parser_id = "VMRay"

    def supports_format(self, trace_path: str) -> bool:
        try:
            with open(trace_path, "rb") as f:
                data = f.read()
            fd = io.BytesIO(data)
            zf = ZipFile(fd)
            zf.setpassword(b"infected")
            if "logs/flog.xml" not in zf.namelist():
                return False

            with zf.open("logs/flog.xml") as flog_xml:
                tree = ET.parse(flog_xml)
                root = tree.getroot()
                return root.find(".//monitor_process") is not None
        except Exception as e:
            return False

    def process_param_val(self, pvalue: str) -> Any:
        if isinstance(pvalue, str) and pvalue.startswith("0x"):
            try:
                return int(pvalue, 16)
            except ValueError:
                pass
        return pvalue

    def get_param_dict(self, param: ET.Element, param_dict: Dict[str, Any]) -> Dict[str, Any]:
        pvalue = param.get("value", "")
        if "name" not in param_dict:
            pname = param.get("name", "")
            param_dict["name"] = pname

        ptype = param.get("type", "")
        if ptype == "ptr":
            deref = param.find("deref")
            if deref is not None:
                deref_type = deref.get("type")
                deref_value = deref.get("value")
                if deref_type == "str":
                    if deref_value is not None:
                        param_dict["value"] = deref_value.replace("\\\\", "\\")
                    else:
                        param_dict["value"] = self.process_param_val(pvalue)
                else:
                    self.get_param_dict(deref, param_dict)
            else:
                param_dict["value"] = self.process_param_val(pvalue)
        elif ptype == "str":
            param_dict["value"] = pvalue
        elif ptype == "container":
            param_dict["value"] = []
            for member in param.findall("member"):
                member_dict = {}
                self.get_param_dict(member, member_dict)
                param_dict["value"].append(member_dict)
        elif ptype == "array":
            param_dict["value"] = []
            for i, item in enumerate(param.findall("item")):
                item_dict = {"name": i}
                param_dict["value"].append(self.get_param_dict(item, item_dict))
        elif ptype == "bindata":
            param_dict["value"] = pvalue
        elif ptype.startswith("signed_") or ptype == "bool":
            try:
                param_dict["value"] = int(pvalue)
            except ValueError:
                param_dict["value"] = pvalue
        else:
            param_dict["value"] = self.process_param_val(pvalue)

        return param_dict

    def _format_call_str(self, call_str_base: str, return_str: str) -> str:
        """Format call string; use IDA-style colors when available, else plain text."""
        try:
            import ida_lines
            from xrefer.gui.helpers import colorize_api_call

            colored_call = colorize_api_call(call_str_base)
            colored_ret = ida_lines.COLSTR(str(return_str), ida_lines.SCOLOR_DSTR)
            return f"{colored_call} \x01{ida_lines.SCOLOR_DEMNAME}=\x02{ida_lines.SCOLOR_DEMNAME} {colored_ret}"
        except Exception as e:
            return f"{call_str_base} = {return_str}"

    def _correlate_memory_regions(self, summary_json: dict, flog_root: ET.Element) -> Dict[str, Dict]:
        """
        Correlates file paths/hashes from summary_v2.json with memory_mapped_file regions in flog.xml.
        Identifies the region corresponding to self.sample_sha256 and if needed, computes a delta.

        Returns a dict:
            {
              monitor_pid_str: {
                'delta': delta_value or 0,
                'regions': [(start_va, end_va), ...]
              },
              ...
            }

        If self.sample_sha256 is set, only returns regions that match that sha256.
        Computes a delta (image_base - region_start) once, if a matching region is found.
        """
        filenames = summary_json.get("filenames", {})
        files = summary_json.get("files", {})
        file_path_hash_values = {}

        # Map file_path -> list of hash sets
        for filename_data in filenames.values():
            file_path = filename_data.get("filename")
            ref_files = filename_data.get("ref_files", [])
            for ref_file in ref_files:
                path = ref_file.get("path", [])
                if len(path) == 2 and path[0] == "files":
                    file_id = path[1]
                    file_metadata = files.get(file_id)
                    if file_metadata:
                        hash_values = file_metadata.get("hash_values")
                        if hash_values:
                            if "_type" in hash_values:
                                hash_values.pop("_type")
                            if file_path not in file_path_hash_values:
                                file_path_hash_values[file_path] = []
                            if hash_values not in file_path_hash_values[file_path]:
                                file_path_hash_values[file_path].append(hash_values)

        # Extract mapped file regions from flog.xml
        mapped_file_regions = {}
        for new_region in flog_root.findall(".//new_region[@region_type='mapped_file']"):
            region_id = "region_" + new_region.get("region_id")
            mapped_file_path = new_region.get("normalized_filename", "").replace("\\\\", "\\")
            mapped_file_regions[region_id] = {"file_path": mapped_file_path}
            if mapped_file_path in file_path_hash_values:
                mapped_file_regions[region_id]["file_hashes"] = file_path_hash_values[mapped_file_path]

        processes_json = summary_json.get("processes", {})
        process_regions = {}

        # Identify and store regions per process
        for proc_key in processes_json:
            proc = processes_json[proc_key]
            monitor_id = proc["monitor_id"]

            region_entries = []
            for region_id, region_data in proc["regions"].items():
                mt = region_data["type"]
                file_hashes = []
                if mt == "memory_mapped_file":
                    mapped_info = mapped_file_regions.get(region_id, {})
                    file_hashes = mapped_info.get("file_hashes", [])
                region_entries.append({"start_va": region_data["start_va"], "end_va": region_data["end_va"], "file_hashes": file_hashes})

            process_regions[str(monitor_id)] = region_entries

        # If we haven't set self.image_base and we have a sample_sha256, find a matching region and compute delta
        process_delta_map = {}
        if self.sample_sha256:
            # Try to find a region that matches self.sample_sha256
            found_delta = False
            for pid, region_list in process_regions.items():
                matching_regions = []
                for region in region_list:
                    for hash_set in region["file_hashes"]:
                        if "sha256" in hash_set and hash_set["sha256"].lower() == self.sample_sha256.lower():
                            # Found a region matching the sha256
                            matching_regions.append((region["start_va"], region["end_va"]))
                            # If image_base not set, set it now
                            if not self.image_base:
                                self.image_base = region["start_va"]
                                log(f"Set image_base to {hex(self.image_base)} from matched region.")

                if matching_regions:
                    # Compute delta if needed
                    # Delta is computed from the first matched region
                    first_region_start = matching_regions[0][0]
                    delta = 0
                    if self.image_base and self.image_base != first_region_start:
                        delta = self.image_base - first_region_start
                        log(f"Computed delta {hex(delta)} for PID {pid} since region start {hex(first_region_start)} != image_base {hex(self.image_base)}")

                    process_delta_map[pid] = {"delta": delta, "regions": matching_regions}

            return process_delta_map
        else:
            # No filtering by sha256, just return all processes with no delta adjustments
            # If image_base not set, we cannot compute a delta anyway
            for pid, region_list in process_regions.items():
                # no sha256 filtering means we consider all regions
                all_regions = [(r["start_va"], r["end_va"]) for r in region_list]
                process_delta_map[pid] = {"delta": 0, "regions": all_regions}
            return process_delta_map

    def parse_trace(self, known_imports: Dict[str, str], trace_path: str) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
        trace_dict = collections.defaultdict(lambda: collections.defaultdict(list))

        if not hasattr(self, "sample_sha256") or not self.sample_sha256:
            log("Warning: sample_sha256 not defined. Will not filter by hash.")

        try:
            with open(trace_path, "rb") as f:
                data = f.read()
            fd = io.BytesIO(data)
            zf = ZipFile(fd)
            zf.setpassword(b"infected")
        except BadZipfile:
            log("[-] Error: Bad zip file")
            return {}

        if "logs/flog.xml" not in zf.namelist() or "logs/summary_v2.json" not in zf.namelist():
            log("[-] Error: flog.xml or summary_v2.json not found in archive.")
            return {}

        try:
            with zf.open("logs/flog.xml") as flog_xml:
                flog_tree = ET.parse(flog_xml)
                flog_root = flog_tree.getroot()

            with zf.open("logs/summary_v2.json") as summary_file:
                summary_json = json.loads(summary_file.read())

            # Correlate memory regions and compute delta
            process_info = self._correlate_memory_regions(summary_json, flog_root)
            if self.sample_sha256 and not process_info:
                log("No matching memory regions found for given SHA256.")
                return {}

            # Build fnret map
            fnret_map = {fnret.get("fncall_id"): int(fnret.get("addr", "0"), 16) for fnret in flog_root.findall(".//fnret")}

            # Process each API call
            for fncall in flog_root.findall(".//fncall"):
                monitor_pid = fncall.get("process_id")

                # If we are filtering by sha256 and no info for this PID, skip
                if self.sample_sha256 and monitor_pid not in process_info:
                    continue

                fncall_id = fncall.get("fncall_id")
                return_addr = fnret_map.get(fncall_id, int(fncall.get("from", "0"), 16))

                # Apply delta if we have it
                delta = 0
                if monitor_pid in process_info:
                    delta = process_info[monitor_pid]["delta"]
                # Adjust return_addr by delta (if any)
                return_addr += delta

                api_name = fncall.get("name", "")
                in_params = []
                out_params = []
                return_value = None

                in_elem = fncall.find("in")
                if in_elem is not None:
                    for param in in_elem.findall("param"):
                        param_dict = {}
                        in_params.append(self.get_param_dict(param, param_dict))

                out_elem = fncall.find("out")
                if out_elem is not None:
                    for param in out_elem.findall("param"):
                        param_dict = {}
                        if param.get("name") == "ret_val":
                            return_value = self.get_param_dict(param, param_dict)["value"]
                        else:
                            out_params.append(self.get_param_dict(param, param_dict))

                # Format call string
                args_str = []
                for param in in_params:
                    name = param.get("name", "")
                    value = param.get("value", "")
                    if name:
                        args_str.append(f"{name}={value}")
                    else:
                        args_str.append(str(value))

                call_str_base = f"({', '.join(args_str)})"
                # TODO(rand0m): This is formatting. Should be in gui/. Refactoring the entire code is needed. No time for this now.  There was a colorize_api_call function in the original code.
                return_str = str(return_value or "0")
                call_str = self._format_call_str(call_str_base, return_str)

                full_name = self.get_standard_api_name(api_name, known_imports)
                formatted_args = self.format_arg_list(in_params)
                call_addr = self.get_call_address(return_addr)
                func_ea = self.get_parent_function(call_addr)

                trace_dict[func_ea][full_name].append(
                    {"index": self.get_next_index(), "args": formatted_args, "call_addr": call_addr, "return_addr": return_addr, "return_value": return_value or "0", "count": 1, "call_str": call_str}
                )

        except Exception as e:
            log(f"[-] Error parsing VMRay trace: {str(e)}")
            return {}

        return self.handle_duplicates(trace_dict)
