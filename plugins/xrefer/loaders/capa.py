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

import json
import os
from typing import Any, Dict, List, Set, Union

import capa.features.freeze as frz
import capa.render.result_document as rd
import capa.render.utils as rutils

from xrefer.backend import get_current_backend
from xrefer.core.helpers import log


def load_capa_json(capa_json_path: str) -> Dict[int, List[Dict[str, Any]]]:
    """
    Load and process CAPA JSON results file.

    Parses CAPA capability analysis results and organizes them by address
    for use in XRefer analysis. Handles image base mismatches by relocating
    addresses appropriately.

    Args:
        capa_json_path (str): Path to CAPA JSON results file

    Returns:
        Dict[int, List[Dict[str, Any]]]: Dictionary mapping addresses to lists of
            rule match information dictionaries
    """

    if not os.path.exists(capa_json_path) or not os.path.isfile(capa_json_path):
        log(f"[-] CAPA JSON file not found: {capa_json_path}")
        return {}
    try:
        doc = get_doc_json_file(capa_json_path)
    except Exception as e:
        log(f"Unable to load {capa_json_path}: {str(e)}")
        return {}

    # Get image bases and calculate relocation delta if needed
    capa_base = doc.meta.analysis.base_address.value

    backend = get_current_backend()
    backend_base = backend.image_base
    relocation_delta = backend_base - capa_base if capa_base != backend_base else 0

    if relocation_delta:
        log(f"Detected image base mismatch: CAPA base=0x{capa_base:x}, backend({backend.name}) base=0x{backend_base:x}")
        log(f"Applying relocation delta: 0x{relocation_delta:x}")

    rmatches = get_rule_matches_dict(doc)

    # If there's a relocation delta, adjust all addresses
    if relocation_delta:
        rmatches = relocate_addresses(rmatches, relocation_delta)

    return rmatches


def get_doc_json_file(json_results_path: str) -> rd.ResultDocument:
    """
    Load and parse CAPA JSON file into ResultDocument.

    Args:
        json_results_path (str): Path to CAPA JSON results file

    Returns:
        rd.ResultDocument: Parsed CAPA result document

    Raises:
        ValueError: If no JSON file provided or located
    """
    if not json_results_path:
        raise ValueError("no capa json file provided and no candidate file located")

    with open(json_results_path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))

    # service wraps raw capa json data under "results"
    results = doc.get("results", doc)
    assert "meta" in results and "rules" in results

    return rd.ResultDocument.parse_obj(results)


def to_locations(addresses: Set[frz.Address]) -> Set[int]:
    """
    Convert CAPA addresses to IDA-compatible locations.

    Handles different types of CAPA addresses (absolute, relative, file)
    and converts them to usable IDA addresses.

    Args:
        addresses (Set[frz.Address]): Set of CAPA addresses to convert

    Returns:
        Set[int]: Set of converted location addresses
    """
    locs = set()
    backend = get_current_backend()
    for addr in addresses:
        if addr.type == frz.AddressType.ABSOLUTE:
            v = addr.value
        elif addr.type == frz.AddressType.RELATIVE:
            v = addr.value
        elif addr.type == frz.AddressType.FILE:
            v = backend.resolve_file_offset(addr.value)
            if v is None:
                continue
        elif addr.type in (frz.AddressType.DN_TOKEN, frz.AddressType.DN_TOKEN_OFFSET, frz.AddressType.NO_ADDRESS):
            continue
        locs.add(v)
    return locs


def get_rule_matches_dict(doc: rd.ResultDocument) -> Dict[int, List[Dict[str, Any]]]:
    """
    Convert CAPA document to dictionary of rule matches.

    Processes CAPA results into a format more suitable for XRefer usage,
    organizing matches by their location/function address.

    Args:
        doc (rd.ResultDocument): CAPA result document

    Returns:
        Dict[int, List[Dict[str, Any]]]: Dictionary where keys are addresses and values are
            lists of dictionaries containing rule match information including:
            - rule_name: Name of matched rule
            - namespace: Rule namespace
            - library: Associated library if any
            - scopes: Rule scopes
            - locations: List of match locations
            - loc_string: Hex string of locations
            - matches: List of nested rule matches
    """
    rmatches = {}
    for rule in rutils.capability_rules(doc):
        rule_name = rule.meta.name
        for address, match in sorted(rule.matches):
            addresses = get_addresses(match)
            locations = sorted(to_locations(addresses))
            rule_match = {
                "rule_name": rule_name,
                "namespace": rule.meta.namespace,
                "library": rule.meta.lib,
                "scopes": rule.meta.scopes,
                "locations": locations,
                "loc_string": hex_list_str(locations),
                "matches": get_matched_rules(match),
            }

            if address.value:
                if address.value not in rmatches:
                    rmatches[address.value] = []
                rmatches[address.value].append(rule_match)

    return rmatches


def get_addresses(match: rd.Match) -> Set[frz.Address]:
    """
    Get all addresses associated with a CAPA match.

    Recursively extracts all addresses from a match and its children,
    excluding addresses of match features themselves.

    Args:
        match (rd.Match): CAPA match object to extract addresses from

    Returns:
        Set[frz.Address]: Set of all relevant addresses for the match
    """
    addresses: Set[frz.Address] = set()

    if not match.success:
        return addresses

    if match.node.type == "feature" and match.node.feature.type == "match":
        return addresses

    addresses.update(match.locations)

    for child in match.children:
        addresses.update(get_addresses(child))

    return addresses


def get_matched_rules(match: rd.Match) -> List[Dict[str, Union[str, List[frz.Address]]]]:
    """
    Get list of all rules matched within a CAPA match.

    Recursively processes a match to extract information about all matched rules,
    including nested matches.

    Args:
        match (rd.Match): CAPA match object to process

    Returns:
        List[Dict[str, Union[str, List[frz.Address]]]]: List of dictionaries containing:
            - name: Name of matched rule
            - locations: List of match locations
            - loc_string: Hex string representation of locations
    """
    matched_rules = []

    if not match.success:
        return matched_rules

    if match.node.type == "feature" and match.node.feature.type == "match":
        matched_rules.append(
            {
                "name": match.node.feature.match,
                "locations": match.locations,
                "loc_string": hex_list_str([loc.value for loc in match.locations if loc.value]),
            }
        )

    for child in match.children:
        matched_rules.extend(get_matched_rules(child))

    return matched_rules


def relocate_addresses(matches: Dict[int, List[Dict[str, Any]]], delta: int) -> Dict[int, List[Dict[str, Any]]]:
    """
    Relocate all addresses in the matches dictionary by the specified delta.

    Args:
        matches: Dictionary of rule matches indexed by address
        delta: Relocation delta to apply to all addresses

    Returns:
        Updated dictionary with relocated addresses
    """
    relocated_matches = {}

    for addr, match_list in matches.items():
        # Relocate the dictionary key (function address)
        new_addr = addr + delta

        # Create new list for relocated matches
        relocated_matches[new_addr] = []

        for match in match_list:
            # Create a copy of the match to modify
            new_match = match.copy()

            # Relocate all locations in the match
            new_match["locations"] = [loc + delta for loc in match["locations"]]

            # Update the location string with relocated addresses
            new_match["loc_string"] = hex_list_str(new_match["locations"])

            # Relocate nested matches
            for nested_match in new_match["matches"]:
                if nested_match.get("locations"):
                    nested_match["locations"] = [addr.value + delta if hasattr(addr, "value") else addr + delta for addr in nested_match["locations"]]
                    nested_match["loc_string"] = hex_list_str(
                        [loc.value if hasattr(loc, "value") else loc for loc in nested_match["locations"] if hasattr(loc, "value") and loc.value or not hasattr(loc, "value")]
                    )

            relocated_matches[new_addr].append(new_match)

    return relocated_matches


def hex_list_str(locations: List[int]) -> str:
    """
    Convert list of addresses to comma-separated hex string.

    Args:
        locations (List[int]): List of addresses to convert

    Returns:
        str: Comma-separated string of hexadecimal values
    """
    return ", ".join([f"0x{loc:X}" for loc in locations])
