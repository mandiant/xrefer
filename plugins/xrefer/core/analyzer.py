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

import os
import ida_lines
import ida_name
import idautils
import idc
import idaapi
import ida_xref
import ida_funcs
import pickle
import json
import gzip
import shutil
from time import time
from PyQt5.QtWidgets import QDialog
from pathlib import Path
from collections import OrderedDict, deque
from operator import itemgetter
from typing import *

from xrefer.core.helpers import *
from xrefer.core.settings import XReferSettingsManager, MissingFilesDialog
from xrefer.core.clusters import ClusterManager, FunctionalCluster
from xrefer.loaders.trace import parse_api_trace
from xrefer.loaders.capa import load_capa_json
from xrefer.lang import get_language_object
from xrefer.llm.base import ModelConfig, ModelType
from xrefer.llm.categorizer import Categorizer, CATEGORIES
from xrefer.llm.artifact_analyzer import ArtifactAnalyzer
from xrefer.llm.cluster_analyzer import ClusterAnalyzer


class XRefer:
    """
    A class for managing and analyzing cross-references in IDA Pro.

    This class handles various types of cross-references, including imports,
    libraries, strings, CAPA matches, and API traces. It provides methods for analyzing
    binary files, managing data structures, and interacting with IDA Pro's API.
    """

    DIRECT_XREFS = 0
    INDIRECT_XREFS = 1
    COMBINED_XREFS = 2

    def __init__(self, ep: Optional[int] = None) -> None:
        """
        Initialize the XRefer object.

        Args:
            ep (Optional[int]): The entry point address. If None, the default entry point will be used.
        """
        try:
            self.settings_manager = XReferSettingsManager()
            self.settings = self.settings_manager.load_settings()
            self.exclusions = self.settings_manager.load_exclusions()

            self.table_names: Dict[int, str] = {
                1: 'INDIRECT LIBRARY XREFS',
                2: 'INDIRECT IMPORT XREFS',
                3: 'INDIRECT STRING XREFS',
                4: 'INDIRECT CAPA XREFS'
            }
            self.entity_type: Dict[int, str] = {
                1: 'libs',
                2: 'imports',
                3: 'strings',
                4: 'capa',
                5: 'api_trace'
            }
            self.entity_suffix_map: Dict[str, str] = {
                'libs': 'libs_ea',
                'imports': 'imports_ea',
                'strings': 'strings_ea',
                'capa': 'capa_ea',
                'api_trace': 'api_trace_ea'
            }
            self.color_tags: Dict[str, int] = {
                self.table_names[1]: ida_lines.SCOLOR_DEMNAME,
                self.table_names[2]: ida_lines.SCOLOR_IMPNAME,
                self.table_names[3]: ida_lines.SCOLOR_DSTR,
                self.table_names[4]: ida_lines.SCOLOR_CODNAME
            }
            # global_xrefs >
            # {func_ea: {self.DIRECT_XREFS: {'libs': set() of entities,
            #                                  'imports': set() of entities,
            #                                  'strings': set() of entities,
            #                                  'capa': set() of entities,
            #                                  'libs_ea': {entity index: set() of addresses},
            #                                  'imports_ea': {entity index: set() of addresses},
            #                                  'strings_ea': {entity index: set() of addresses},
            #                                  'capa_ea': {entity index: set() of addresses}},
            #           self.INDIRECT_XREFS: ...,
            #           self.COMBINED_XREFS: set() of all entities (libs, imports, strings, capa) }}
            #
            # string_index_cache >
            # list of string index (for self.entities)
            #
            # caller_xrefs_cache >
            # {func_ea: {referenced item (string, lib, import, capa) address:
            #                                   set() of addresses within func_ea method referencing that item }}
            #
            # paths > all paths from entrypoint to a function
            # {func_ea: list() containing lists of paths}
            #
            # table_data >
            # {func_ea: OrderedDict() > {table_name: {heading: [],
            #                                         rows: OrderedDict() > {inner_table_name: list() of rows
            #                                                                                   as strings}
            #
            # entities >
            # list() of tuple(group_name, entity text (api, lib, capa or string),
            #                                          entity type index, group_name extra detail text)
            #
            # reverse_entity_lookup_index >
            # {entity (api, lib, capa or string text): index of that entity in self.entities
            #
            # entity_xrefs >
            # {entity (api, lib, capa or string) index: set() of all xref addresses for that entity
            #
            # graph_cache >
            # {entity index: ascii text based graph string}

            self.lang: Any = None
            self.capa_matches: Optional[Dict[int, List[Dict[str, Any]]]] = None
            self.categories: Optional[Dict[str, Any]] = None
            self.current_analysis_ep: Optional[int] = ep
            self.imports: List[Tuple[int, int, int]] = []
            self.strings: List[List[Tuple[int, int, int]]] = [[], []]
            self.lib_refs: List[Tuple[int, int, int]] = []
            self.mapped_refs: List[Tuple[int, int, int]] = []
            self.api_trace_data: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}
            self.global_xrefs: Dict[int, Dict[int, Dict[str, Union[Set[int], Dict[int, Set[int]]]]]] = {}
            self.string_index_cache: List[int] = []
            self.caller_xrefs_cache: Dict[int, Dict[int, Set[int]]] = {}
            self.graph_cache: Dict[int, List[str]] = {}
            self.paths: Dict[int, Dict[int, List[List[int]]]] = {}
            self.table_data: Dict[int, Dict[str, Dict[str, Union[List[str], OrderedDict]]]] = {}
            self.entities: List[Tuple[str, str, int, str]] = []
            self.reverse_entity_lookup_index: Dict[str, int] = {}
            self.entity_xrefs: Dict[int, Set[int]] = {}
            self.excluded_entities: Set[int] = set()
            self.interesting_artifacts: Set[int] = set()
            self.leaf_funcs: Set[int] = set()
            self.git_lookups: bool = True
            self.llm_lookups: bool = True
            self.image_base: int = idaapi.get_imagebase()
            self.idb_path: str = idc.get_idb_path()
            self.plugin_subdir_path: str = str(Path(__file__).resolve().parent.parent)
            self._processed_orphan_thunks: Set[int] = set()
            self.clusters = None
            self.cluster_analysis = None
            self.configure_llm_and_lookups()
            self.load_analysis()

        finally:
            idaapi.hide_wait_box()

    def process_exclusions(self) -> None:
        """
        Process exclusions against entities before context table population.
        Only checks for dots in API names, uses full names for other types.
        """
        log('Processing exclusions')

        # Reset excluded entities
        self.excluded_entities.clear()
        
        # Load exclusions
        settings_manager = XReferSettingsManager()
        exclusions = settings_manager.load_exclusions()
            
        exclusion_maps = {
            1: set(name.lower() for name in exclusions['libs']),     # lib type
            2: set(name.lower() for name in exclusions['apis']),     # api type
            3: set(name.lower() for name in exclusions['strings']),  # string type
            4: set(name.lower() for name in exclusions['capa'])      # capa type
        }
        
        # Pre-compile regex for API suffix extraction
        suffix_pattern = re.compile(r'[^.]*$')
        
        # Process all entities in a single pass
        for entity_index, entity in enumerate(self.entities):
            entity_type = entity[2]  # Type is third element
            entity_name = entity[1]  # Full name is second element
            
            # Skip if entity type not in our exclusions maps
            if entity_type not in exclusion_maps:
                continue
                
            # Get the relevant exclusions set
            exclusion_set = exclusion_maps[entity_type]
            if not exclusion_set:
                continue
                
            # Only extract suffix for APIs, use full name for others
            if entity_type == 2 and '.' in entity_name:  # API type
                name = suffix_pattern.search(entity_name).group(0).lower()
            else:
                name = entity_name.lower()
                
            # Check if name matches any exclusions entry
            if name in exclusion_set:
                self.excluded_entities.add(entity_index)
        
        # Regenerate artifact functions list after updating exclusions
        self.generate_list_of_non_excluded_functions()

    def get_functions_with_excluded_items(self) -> Set[int]:
        """
        Get set of functions that contain any excluded items either directly or indirectly.
        
        Returns:
            Set[int]: Set of function addresses that need table updates
        """
        affected_funcs = set()
            
        # Check all functions that have xrefs
        for func_ea, xrefs in self.global_xrefs.items():
            # Check direct xrefs
            direct_xrefs = xrefs[self.DIRECT_XREFS]
            for xref_type in ('libs', 'imports', 'strings', 'capa'):
                if any(entity in self.excluded_entities for entity in direct_xrefs[xref_type]):
                    affected_funcs.add(func_ea)
                    break  # No need to check other types for this function
                    
            # If not already added, check indirect xrefs
            if func_ea not in affected_funcs:
                indirect_xrefs = xrefs[self.INDIRECT_XREFS]
                for xref_type in ('libs', 'imports', 'strings', 'capa'):
                    if any(entity in self.excluded_entities for entity in indirect_xrefs[xref_type]):
                        affected_funcs.add(func_ea)
                        break  # No need to check other types for this function
                        
        return affected_funcs

    def reload_settings(self):
        self.settings = self.settings_manager.load_settings()
        self.exclusions = self.settings_manager.load_exclusions()
        self.configure_llm_and_lookups()
        self.process_exclusions()

    def get_lang_object(self) -> Any:
        """Get appropriate language object for the current binary.""" 
        return get_language_object()

    def sift_libs(self) -> None:
        """
        Process and categorize library references.
        
        Uses LLM categorization if enabled to classify library references,
        otherwise maintains original grouping. Handles enrichment of
        library metadata and updates global library reference lists.
        
        Side Effects:
            - Updates self.categories with library categorizations
            - Updates self.lib_refs with processed references
            - Creates entity indices for libraries
        """
        if not self.lang.lib_refs:
            return

        log('Sifting library references...')
        lib_list = [x[1] for x in self.lang.lib_refs]

        if self.llm_lookups:
            _, self.categories['lib_categories'] = Categorizer.categorize(lib_list, self.categories['libs'], type='lib')

        for lib_ref in self.lang.lib_refs:
            try:
                category_index = self.categories['libs'][lib_ref[1]]
                category = self.categories['lib_categories'][category_index]
                entity = (category, lib_ref[1], 1)
            except:
                entity = (lib_ref[3], lib_ref[1], 1)
            e_index = self.set_and_get_entity_index(entity)
            self.lib_refs.append((lib_ref[0], e_index, lib_ref[2]))

    def sift_strings(self) -> None:
        """
        Process and organize string references.
        
        Handles string extraction, deduplication, and entity creation.
        Processes both simple strings and complex string references with
        additional metadata.
        
        Side Effects:
            - Updates self.strings lists for different string types
            - Creates entity indices for strings
            - Updates string_index_cache
            
        Note:
            Maintains two string lists:
            - strings[0]: Simple string references
            - strings[1]: Extended string references with additional data
        """
        log('Sifting string references...')
        for str_ea in self.lang.strings:
            string_contents = self.lang.strings[str_ea][0]
            if len(string_contents) >= 3:
                entity = string_contents.strip()

                if '\n' in entity:
                    entity = entity.replace('\n', '\\n').replace('\r', '\\r')
                
                e_index = self.set_and_get_entity_index(entity)
                
                if len(self.lang.strings[str_ea]) == 3:
                    self.strings[1].append((str_ea, e_index, 3, self.lang.strings[str_ea][2]))
                else:
                    self.strings[0].append((str_ea, e_index, 3))

                if e_index not in self.string_index_cache:
                    self.string_index_cache.append(e_index)

    def sift_capa_matches(self) -> None:
        """
        Process and categorize CAPA matches.

        This method goes through the CAPA matches, processes them,
        and adds them to the capa_matches list.
        """
        if not self.capa_matches:
            return

        log('Sifting capa matches...')
        sifted_list = []

        for addr, rule_matches in self.capa_matches.items():
            for rule_match in rule_matches:
                if not rule_match['library']:
                    namespace = rule_match['namespace'].split('/')
                    if len(namespace) == 1:
                        namespace = namespace[0]
                    else:
                        namespace = '/'.join(namespace[0:2])
                    entity = (namespace, rule_match['rule_name'], 4)
                    e_index = self.set_and_get_entity_index(entity)
                    for _addr in rule_match['locations']:
                        if idc.func_contains(_addr, _addr):
                            sifted_list.append((_addr, e_index, 4))

        self.capa_matches = sifted_list

    def find_interesting_artifacts(self) -> None:
        """
        Analyze entities for potentially interesting/malicious indicators.
        
        Uses LLM analysis to identify potentially significant artifacts
        across different types (APIs, strings, libraries, CAPA matches).
        Considers context and relationships between artifacts.
        
        Side Effects:
            - Updates self.interesting_artifacts with identified indices
            - Logs summary of findings by type
            
        Note:
            - Only runs if LLM lookups are enabled
            - Respects current exclusions settings
            - Groups findings by type for reporting
        """
        if not self.llm_lookups:
            log("LLM lookups disabled - skipping artifact analysis")
            return
            
        log("Analyzing entities for interesting artifacts...")
            
        try:
            # Format entities for analysis
            artifacts = []
            
            # Map entity type_id to prompt type
            type_mapping = {
                1: "lib",     # Library references
                2: "api",     # API calls
                3: "string",  # Strings
                4: "capa"     # CAPA matches
            }
            
            for idx, entity in enumerate(self.entities):
                # All entities have at least these 3 fields
                if len(entity) < 3:
                    continue
                    
                type_id = entity[2]    # Type ID is always at index 2
                if type_id not in type_mapping:
                    continue
                    
                category = entity[0]   # Category/group name always at index 0
                content = entity[1]    # Content always at index 1
                
                artifact = {
                    "type": type_mapping[type_id],
                    "index": idx,
                    "content": content,
                    "category": category
                }
                
                # Handle enriched string entities
                if type_id == 3 and len(entity) > 4:  # String type with Git enrichment
                    try:
                        # Index 4 has matched lines dictionary
                        artifact["context"] = entity[4]
                        # Index 6 has full string if available
                        if len(entity) > 6:
                            artifact["full_content"] = entity[6]
                    except IndexError:
                        pass  # Skip enrichment if indices not available
                        
                artifacts.append(artifact)
                
            if not artifacts:
                log("No artifacts found for analysis")
                return
                
            # Get interesting artifacts
            interesting_artifacts = ArtifactAnalyzer.find_interesting_artifacts(artifacts)
            
            # Store results
            self.interesting_artifacts = interesting_artifacts
            
            # Log summary by type
            type_counts = {t: 0 for t in ["string", "api", "lib", "capa"]}
            for idx in interesting_artifacts:
                if idx >= len(self.entities):
                    continue
                entity_type = type_mapping.get(self.entities[idx][2])
                if entity_type:
                    type_counts[entity_type] += 1
                    
            summary = ", ".join(f"{count} {t}s" for t, count in type_counts.items() if count > 0)
            log(f"Found {len(interesting_artifacts)} potential interesting artifacts: {summary}")
            
        except Exception as e:
            log(f"Error during interesting artifact analysis: {str(e)}")
            self.malicious_indicators = set()

    def process_api_trace(self) -> None:
        """
        Process and integrate API trace data.
        
        Parses API trace file and integrates trace information with
        existing cross-reference data. Handles dynamic API resolution
        and call site correlation.
        
        Side Effects:
            - Updates self.api_trace_data with parsed trace
            - Updates global_xrefs with trace references
            - Creates new entities for dynamic APIs
            - Updates entity_xrefs for API calls
            
        Note:
            Handles different API types:
            - Static APIs with known imports
            - Dynamic APIs without static references
            - NT/Native APIs from ntdll
        """
        log('Processing API trace...')

        # Create a mapping of API names to their full names (including module)
        known_imports = {}
        for entity in self.entities:
            if len(entity) >= 3 and entity[2] == 2:
                api_name = entity[1].split('.')[-1]
                known_imports[api_name] = entity[1]

        # Parse and standardize API trace data
        self.api_trace_data = parse_api_trace(known_imports, self.settings['paths']['trace'])

        # Process xrefs
        for parent_func_ea, api_calls in self.api_trace_data.items():
            if parent_func_ea not in self.global_xrefs:
                self.global_xrefs[parent_func_ea] = {
                    self.DIRECT_XREFS: self.init_global_xrefs_template(),
                    self.INDIRECT_XREFS: self.init_global_xrefs_template(),
                    self.COMBINED_XREFS: set()
                }

            # other than detecting indirect api calls for a function, this is redundant atm. need to fix this.
            self.global_xrefs[parent_func_ea][self.DIRECT_XREFS]['api_trace'].add(parent_func_ea)

            for full_api_name in api_calls:
                is_dynamic = full_api_name.startswith('dynamic.')
                module_name, api_name = full_api_name.split('.')
                if is_dynamic:
                    entity = ('Non-Static API References', full_api_name, 2)
                    entity_index = self.set_and_get_entity_index(entity)
                    for api_call in self.api_trace_data[parent_func_ea][full_api_name]:
                        ea = api_call['call_addr']
                        self.imports.append((ea, entity_index, 2))
                elif full_api_name.startswith('ntdll.'):
                    entity = ('Low-level API References', full_api_name, 2)
                    entity_index = self.set_and_get_entity_index(entity)
                    for api_call in self.api_trace_data[parent_func_ea][full_api_name]:
                        ea = api_call['call_addr']
                        self.imports.append((ea, entity_index, 2))
                else:
                    try:
                        category_index = self.categories['apis'][full_api_name]
                        category = self.categories['api_categories'][category_index]
                        entity = (category, full_api_name, 2)
                    except:
                        entity = (module_name, full_api_name, 2)

                    entity_index = self.set_and_get_entity_index(entity)

                if entity_index not in self.entity_xrefs:
                    self.entity_xrefs[entity_index] = set()
                self.entity_xrefs[entity_index].add(parent_func_ea)


        log(f'Processed API traces for {len(self.api_trace_data)} functions')

    def create_xref_mapping(self) -> None:
        """
        Generate comprehensive cross-reference mappings.
        
        Creates detailed mapping of all cross-references between functions,
        handling both direct and indirect references. Critical for path
        analysis and boundary scanning.
        
        Side Effects:
            - Populates caller_xrefs_cache with structured reference data
            
        Note:
            For each function, maps:
            - References to other functions
            - Specific call sites within function
            - Both direct and computed references
        """

        log('Generating xref mappings...')
        for func in idautils.Functions():
            start = idc.get_func_attr(func, idc.FUNCATTR_START)
            end = idc.prev_addr(idc.get_func_attr(func, idc.FUNCATTR_END))

            _func = idaapi.get_func(func)

            if not _func:
                continue

            # Iterate over basic blocks in the function
            flowchart = idaapi.FlowChart(_func)
            for block in flowchart:
                # Iterate over the instructions in the basic block
                for addr in idautils.Heads(block.start_ea, block.end_ea):
                    func_refs_from = idautils.XrefsFrom(addr, 1)
                    for ref in func_refs_from:
                        # Check if the reference points within the same function
                        ref_to = ida_funcs.get_func(ref.to)
                        if ref_to and ref_to == ida_funcs.get_func(start):
                            continue

                        if start not in self.caller_xrefs_cache:
                            # function A -> function B call locations
                            self.caller_xrefs_cache[start] = {ref.to: {ref.frm}}
                        else:
                            try:
                                self.caller_xrefs_cache[start][ref.to].add(ref.frm)
                            except:
                                self.caller_xrefs_cache[start][ref.to] = {ref.frm}

    def get_user_xrefs(self, user_xrefs_path: str):
        try:
            _xrefs = []

            with open(user_xrefs_path, 'r') as infile:
                xrefs = infile.read().splitlines()

            for line in xrefs:
                if len(line) > 1:
                    xref_tup = line.split(',')
                    xref_frm = int(xref_tup[0].strip(), 16)
                    xref_to = int(xref_tup[1].strip(), 16)
                    _xrefs.append((xref_frm, xref_to))

            return _xrefs

        except Exception as err:
            log(f'No user xrefs loaded')
            return []

    def add_user_xrefs(self) -> None:
        """
        Add user-defined cross-references to IDA Pro.

        This method adds user-defined cross-references to the IDA database
        and annotates them with comments.
        """
        user_xrefs = self.get_user_xrefs(self.settings['paths']['xrefs'])
        self.lang.user_xrefs.extend(user_xrefs)

        for xref in self.lang.user_xrefs:
            log(f'Adding indirect xref: 0x{xref[0]:x} -> 0x{xref[1]:x}')
            ida_xref.add_cref(xref[0], xref[1], idc.XREF_USER)
            idc.set_cmt(xref[0], '[xrefer] 0x%x' % xref[1], 0)

    def init_global_xrefs_template(self) -> Dict[str, Union[Set[int], Dict[int, Set[int]]]]:
        """
        Initialize a template for global cross-references.

        Returns:
            Dict[str, Union[Set[int], Dict[int, Set[int]]]]: A dictionary template for global cross-references.
        """
        return {
            'libs': set(), 'imports': set(), 'strings': set(), 'capa': set(), 'api_trace': set(),
            'libs_ea': {}, 'imports_ea': {}, 'strings_ea': {}, 'capa_ea': {}, 'api_trace_ea': {}
        }

    def set_and_get_entity_index(self, entity: Tuple[str, str, int]) -> int:
        """
        Get the index of an entity, adding it to the list if not already present.

        Args:
            entity (Tuple[str, str, int]): The entity to look up or add.

        Returns:
            int: The index of the entity in the entities list.
        """
        for index, _entity in enumerate(self.entities):
            if entity == _entity:
                return index

        self.entities.append(entity)
        return len(self.entities) - 1

    def load_imports(self) -> None:
        """
        Load and process import information from the binary.

        This method enumerates the imports of the currently loaded module,
        categorizes them if enabled, and adds them to the imports list.
        """
        log('Getting imports...')
        entries = []
        for i in range(idaapi.get_import_module_qty()):
            module_name = idaapi.get_import_module_name(i)
            if not module_name:
                continue

            module_name = module_name.lower().split('/')[-1]

            def cb(ea: int, name: str, ordinal: int) -> bool:
                _module_name = None
                if '@@' in name:  # elf dynsyms
                    splitted = name.split('@@')
                    name = splitted[0]
                    if '_' in splitted[1]:
                        _module_name = '_'.join(splitted[1].split('_')[:-1])
                    else:
                        _module_name = splitted[1]
                if _module_name is None:
                    entries.append((ea, f'{module_name}.{name}', ordinal, module_name))
                else:
                    entries.append((ea, f'{_module_name}.{name}', ordinal, _module_name))
                return True

            idaapi.enum_import_names(i, cb)

        api_list = [x[1] for x in entries]
        if self.llm_lookups:
            _, self.categories['api_categories'] = Categorizer.categorize(api_list, self.categories['apis'])

        for ea, name, _, module_name in entries:
            try:
                category_index = self.categories['apis'][name]
                category = self.categories['api_categories'][category_index]
                entity = (category, name, 2)
            except:
                entity = (module_name, name, 2)

            self.entities.append(entity)
            self.imports.append((ea, len(self.entities) - 1, 2))

    def merge_xrefs(self, func_ea: int, child_func_ea: int) -> bool:
        """
        Merge cross-references from a child function into a parent function.

        Args:
            func_ea (int): The address of the parent function.
            child_func_ea (int): The address of the child function.

        Returns:
            bool: True if any cross-references were modified, False otherwise.
        """
        modified = False
        xref_types = ('libs', 'imports', 'strings', 'capa', 'api_trace')

        try:
            parent_xrefs = self.global_xrefs[func_ea]
            child_xrefs = self.global_xrefs[child_func_ea]
        except KeyError:
            # Initialize if not present
            parent_xrefs = self.global_xrefs.setdefault(func_ea, {
                self.DIRECT_XREFS: self.init_global_xrefs_template(),
                self.INDIRECT_XREFS: self.init_global_xrefs_template(),
                self.COMBINED_XREFS: set()
            })
            child_xrefs = self.global_xrefs.setdefault(child_func_ea, {
                self.DIRECT_XREFS: self.init_global_xrefs_template(),
                self.INDIRECT_XREFS: self.init_global_xrefs_template(),
                self.COMBINED_XREFS: set()
            })

        for xref_type in xref_types:
            parent_indirect = parent_xrefs[self.INDIRECT_XREFS][xref_type]
            for index in (self.DIRECT_XREFS, self.INDIRECT_XREFS):
                child_set = child_xrefs[index][xref_type]
                if child_set:
                    new_xrefs = child_set - parent_indirect
                    if new_xrefs:
                        parent_indirect.update(new_xrefs)
                        modified = True

        return modified

    def map_refs_to_leaf_functions(self, ref_list: List[Tuple[int, int, int]]) -> None:
        """
        Map references to their containing leaf functions.
        
        Processes list of references and associates them with their
        containing functions, handling various reference types and
        ensuring proper function containment.
        
        Args:
            ref_list: List of tuples containing (address, item, type)
            
        Side Effects:
            - Updates self.mapped_refs with processed references
            - Updates self.leaf_funcs with identified leaf functions
            
        Note:
            Handles special cases:
            - Flow references within functions
            - References from library functions
            - Data references
            - Indirect references
        """
        log('Mapping references to leaf functions...')
        ref_to_search = []

        while ref_list:
            addr, item, type = ref_list.pop()
            func = idaapi.get_func(addr)

            # If 'addr' is the start of a function, check if it's a library function
            if func and func.start_ea != idaapi.BADADDR and func.start_ea == addr:
                func_flags = idc.get_func_flags(func.start_ea)
                # If it's a user-defined function, map directly
                if (func_flags & idc.FUNC_LIB) == 0:
                    self.mapped_refs.append((addr, item, type))
                    continue
                # If it's a library function, do not continue here. We fall through to XrefsTo() below.

            # Find cross-references to 'addr' and try to resolve them
            for xref in idautils.XrefsTo(addr):
                if idc.func_contains(xref.frm, xref.frm):
                    # Cross-reference is within a function
                    if xref.type == ida_xref.fl_F:
                        # Ordinary flow reference, use the original address
                        self.mapped_refs.append((addr, item, type))
                    # If not a library function, we map from the caller
                    elif (idc.get_func_flags(xref.frm) & idc.FUNC_LIB) == 0:
                        self.mapped_refs.append((xref.frm, item, type))
                elif xref.type in (
                    ida_xref.fl_U, ida_xref.dr_O, ida_xref.dr_W,
                    ida_xref.dr_R, ida_xref.dr_T, ida_xref.dr_I
                ):
                    # Indirect or data reference, we store it for another iteration
                    ref_to_search.append((xref.frm, item, type))

            # If ref_list is empty, swap in the refs we found this round
            if not ref_list:
                ref_list = ref_to_search
                ref_to_search = []

    def propagate_xref_nodes(self, iter: int) -> bool:
        """
        Propagate cross-reference information through call paths.
        
        Iteratively propagates cross-reference information up call chains,
        ensuring complete visibility of references through call paths.
        Critical for boundary analysis and path tracking.
        
        Args:
            iter (int): Current iteration number for logging
            
        Returns:
            bool: True if any modifications were made during propagation
            
        Side Effects:
            - Updates global_xrefs with propagated reference information
            
        Note:
            - Handles both direct and indirect references
            - Maintains reference type distinction during propagation
            - Updates entity visibility through call chains
        """
        total = len(self.paths[self.current_analysis_ep]) - 1
        modified = False

        for index, (_, path_group) in enumerate(self.paths[self.current_analysis_ep].items()):
            log(f'Propagating xref nodes :: [pass {iter}] :: [{index}/{total}]')
            for path in path_group:
                child_func_ea = None

                for func_ea in reversed(path):
                    if child_func_ea:
                        ret = self.merge_xrefs(func_ea, child_func_ea)
                        if ret:
                            modified = ret
                    child_func_ea = func_ea

        return modified

    def fix_thunk_xrefs(self) -> None:
        """
        Fix cross-references for thunk functions.

        This method adjusts cross-references related to thunk functions
        to ensure proper analysis and display of references.
        """
        log(f'Fixing thunk function references...')

        for index, (_, path_group) in enumerate(self.paths[self.current_analysis_ep].items()):
            for path in path_group:
                child_func_ea = None
                for _index, func_ea in enumerate(reversed(path)):
                    if _index == 1 and idc.get_func_flags(child_func_ea) & idc.FUNC_THUNK and \
                            self.global_xrefs[child_func_ea][self.DIRECT_XREFS]['imports']:

                        node = next(iter(self.global_xrefs[child_func_ea][self.DIRECT_XREFS]['imports']))
                        self.global_xrefs[func_ea][self.DIRECT_XREFS]['imports'].add(node)
                        try:
                            if node not in self.global_xrefs[func_ea][self.DIRECT_XREFS]['imports_ea']:
                                call_xrefs = self.caller_xrefs_cache[func_ea][child_func_ea]
                                self.global_xrefs[func_ea][self.DIRECT_XREFS]['imports_ea'][node] = call_xrefs
                                self.entity_xrefs[node].update(call_xrefs)
                        except:
                            pass
                        self.global_xrefs[func_ea][self.INDIRECT_XREFS]['imports'].discard(node)
                        break

                    child_func_ea = func_ea

    def _process_artifact_xrefs(self, idx: int, entity: Tuple, xrefs: Set[int],
                            func_artifacts: Dict, orphan_func_artifacts: Dict,
                            orphan_artifacts: List) -> None:
        """
        Process cross-references for an artifact and categorize it.
        """
        # Early return if artifact has more than 2 xrefs
        if len(xrefs) > 2:
            return
                
        artifact_sorted = False
        # Create a copy of xrefs set to safely iterate over
        for xref in set(xrefs):  # Create a copy here
            func = idaapi.get_func(xref)
            if not func:
                continue
                        
            func_ea = func.start_ea
            if idc.get_func_flags(func_ea) & idc.FUNC_THUNK:
                continue
                    
            # Use orphan check that considers indirect xrefs
            is_orphan = self.is_orphan_function(func_ea)
                
            if not is_orphan:
                if func_ea not in func_artifacts:
                    func_artifacts[func_ea] = []
                artifact_entry = (entity[2], entity[1], xref)
                if artifact_entry[:2] not in [(x[0], x[1]) for x in func_artifacts[func_ea]]:
                    func_artifacts[func_ea].append(artifact_entry)
                artifact_sorted = True
            else:
                if func_ea in self.table_data:
                    self.table_data[func_ea] = self.create_sorted_table(func_ea)
                if func_ea not in orphan_func_artifacts:
                    orphan_func_artifacts[func_ea] = []
                artifact_entry = (entity[2], entity[1], xref)
                if artifact_entry[:2] not in [(x[0], x[1]) for x in orphan_func_artifacts[func_ea]]:
                    orphan_func_artifacts[func_ea].append(artifact_entry)
                artifact_sorted = True
                        
        if not artifact_sorted:
            orphan_artifacts.append((entity[2], entity[1]))

    def _group_interesting_artifacts(self, interesting_indices: Set[int]) -> Tuple[Dict, Dict, List]:
        """
        Group interesting artifacts by function and orphan status.
        Only includes artifacts with 5 or fewer cross-references.
        
        Args:
            interesting_indices: Set of indices of interesting artifacts
            
        Returns:
            Tuple[Dict, Dict, List]: Tuple containing:
                - Dictionary of reachable function artifacts
                - Dictionary of orphaned function artifacts
                - List of completely orphaned artifacts
        """
        func_artifacts = {}  # {func_ea: [(entity_type, entity_name, xref_addr), ...]}
        orphan_func_artifacts = {}  # Same structure for orphans
        orphan_artifacts = []  # For artifacts with no xrefs at all
        
        # Filter out excluded artifacts and those with >2 xrefs
        filtered_indices = set()
        for idx in interesting_indices:
            if self.settings['enable_exclusions']:
                if idx in self.excluded_entities:
                    continue
            # Check xref count before adding
            if idx not in self.entity_xrefs:
                self.populate_entity_xrefs(idx)
            xrefs = self.entity_xrefs.get(idx, set())
            if len(xrefs) <= 2:  # Only include if 5 or fewer xrefs
                filtered_indices.add(idx)
        
        # Process remaining artifacts
        for idx in filtered_indices:
            entity = self.entities[idx]
            xrefs = self.entity_xrefs.get(idx, set())
            
            # Handle artifacts based on their xrefs
            if not xrefs:
                orphan_artifacts.append((entity[2], entity[1]))
                continue
                
            self._process_artifact_xrefs(idx, entity, xrefs, func_artifacts, 
                                    orphan_func_artifacts, orphan_artifacts)
                                
        return func_artifacts, orphan_func_artifacts, orphan_artifacts

    def populate_entity_xrefs(self, entity_idx: int) -> None:
        """Quickly populate xrefs for a specific entity."""
        entity = self.entities[entity_idx]
        entity_type = entity[2]  # Type ID of entity
        
        # Search through mapped refs to find xrefs for this entity
        for ref in self.mapped_refs:
            if ref[1] == entity_idx:  # If entity index matches
                if entity_idx not in self.entity_xrefs:
                    self.entity_xrefs[entity_idx] = set()
                self.entity_xrefs[entity_idx].add(ref[0])

    def has_indirect_xrefs(self, func_ea: int) -> bool:
        """
        Check if a function has any indirect xrefs, including _ea dictionary entries.
        
        Args:
            func_ea (int): Function address to check
            
        Returns:
            bool: True if function has any indirect xrefs
        """
        try:
            indirect_xrefs = self.global_xrefs[func_ea][self.INDIRECT_XREFS]
            
            # Check basic indirect xref sets
            for xref_type in ('libs', 'imports', 'strings', 'capa', 'api_trace'):
                if indirect_xrefs[xref_type]:
                    return True
                    
            # Check corresponding _ea dictionary entries
            for xref_type in ('libs_ea', 'imports_ea', 'strings_ea', 'capa_ea', 'api_trace_ea'):
                if indirect_xrefs[xref_type]:  # If the dictionary has any entries
                    return True
                    
            return False
        except KeyError:
            return False

    def is_orphan_function(self, func_ea: int) -> bool:
        """
        Determine if a function is orphaned by checking both path reachability
        and indirect xrefs.
        
        Args:
            func_ea (int): Function address to check
            
        Returns:
            bool: True if function is orphaned (no paths from entry and no indirect xrefs)
        """
        # First check if reachable from any entry point
        for ep in self.paths:
            if func_ea in self.paths[ep] or func_ea == ep:
                return False
                
        # If not reachable, check for indirect xrefs
        return not self.has_indirect_xrefs(func_ea)

    def populate_xref_addrs(self) -> None:
        """
        Populate cross-reference addresses through paths.

        This method fills in the cross-reference address information
        for all functions in the analyzed paths.
        """
        total = len(self.paths[self.current_analysis_ep]) - 1
        for index, (_, path_group) in enumerate(self.paths[self.current_analysis_ep].items()):
            log(f'Populating xref addresses :: [{index}/{total}]')
            for path in path_group:
                child_func_ea = None
                for func_ea in reversed(path):
                    for xref_type in 'libs', 'imports', 'strings', 'capa', 'api_trace':
                        for xref_cat in self.DIRECT_XREFS, self.INDIRECT_XREFS:
                            self.global_xrefs[func_ea][self.COMBINED_XREFS].update(
                                self.global_xrefs[func_ea][xref_cat][xref_type])
                            try:
                                for xref in self.global_xrefs[child_func_ea][xref_cat][xref_type]:
                                    try:
                                        self.global_xrefs[func_ea][self.INDIRECT_XREFS][
                                            self.entity_suffix_map[xref_type]][
                                            xref].add(child_func_ea)
                                    except KeyError:
                                        self.global_xrefs[func_ea][self.INDIRECT_XREFS][
                                            self.entity_suffix_map[xref_type]][
                                            xref] = {child_func_ea}
                            except KeyError:
                                pass

                    child_func_ea = func_ea

    def generate_reverse_entity_lookup_index(self) -> None:
        """
        Generate a reverse lookup index for entities.

        This method creates a dictionary that maps entity names to their indices
        in the entities list for quick lookup.
        """
        log('Generating reverse entity lookup index...')
        for index, entity in enumerate(self.entities):
            self.reverse_entity_lookup_index[entity[1]] = index

    def simplify_path(self, path: List[int]) -> List[int]:
        """
        Simplify a path by removing nodes that don't have artifacts and connecting their neighbors.
        
        Args:
            path (List[int]): Original path
            
        Returns:
            List[int]: Simplified path with non-artifact nodes removed
        """
        simplified = []
        for node in path:
            # Always include the first and last nodes
            if not simplified or node == path[-1]:
                simplified.append(node)
            # For middle nodes, only include if they have artifacts
            elif node in self.artifact_functions:
                simplified.append(node)
        return simplified
    
    def find_cluster_by_id(self, cluster_id: int) -> Optional["FunctionalCluster"]:
        """
        Find cluster object by its ID, recursively searching through all clusters and subclusters.
        
        Args:
            cluster_id: ID of cluster to find
            
        Returns:
            Optional[FunctionalCluster]: The cluster if found, None otherwise
        """
        def search_clusters(clusters):
            for cluster in clusters:
                # Direct ID match
                if cluster.id == cluster_id:
                    return cluster
                    
                # Search subclusters recursively
                for subcluster in cluster.subclusters:
                    result = search_clusters([subcluster])
                    if result:
                        return result
                        
                # If cluster contains the reference we're looking for
                if cluster_id in cluster.cluster_refs.values():
                    return cluster_map.get(cluster_id)
                    
            return None

        # Initialize cluster_map for reference resolution
        cluster_map = {}
        cluster_queue = list(self.clusters)
        while cluster_queue:
            cluster = cluster_queue.pop(0)
            cluster_map[cluster.id] = cluster
            cluster_queue.extend(cluster.subclusters)
            
        result = search_clusters(self.clusters)
        if result:
            return result
            
        # Final fallback - check if it's a missing but referenced cluster
        if str(cluster_id) in [str(c) for c in self.cluster_analysis.get('missing_clusters', [])]:
            log(f"Cluster {cluster_id} is referenced but missing from hierarchy")
            
        return None
    
    def analyze_clusters(self, entities_to_cluster) -> None:
        """Create clusters based on interesting nodes first, using only shortest intermediate paths."""
        # Store current state
        current_clusters = self.clusters
        current_analysis = self.cluster_analysis
        
        try:
            # Get interesting functions
            func_artifacts, orphan_func_artifacts, _ = self._group_interesting_artifacts(
                entities_to_cluster)
                
            all_candidate_funcs = set(func_artifacts.keys()) | set(orphan_func_artifacts.keys())
            
            if not all_candidate_funcs:
                log("No candidate functions found for clustering")
                return
                
            # Reset cluster IDs for new analysis
            FunctionalCluster.reset_id_counter()
            self.clusters = []
            self.cluster_analysis = {}
            
            # Data structures for path processing
            graph_paths = []  # Simplified paths for graph construction
            seen_paths = set()  # Track unique paths
            root_nodes = set()  # Entry points
            intermediate_paths_map = {}  # Map node pairs to shortest intermediate paths
            
            # Process each path to find root nodes and track intermediates
            for ep in self.paths:
                for func_ea, paths in self.paths[ep].items():
                    if func_ea in all_candidate_funcs:
                        for path in paths:
                            path_tuple = tuple(path)
                            if path_tuple not in seen_paths:
                                seen_paths.add(path_tuple)
                                # Get simplified path and intermediates
                                simplified, path_intermediates = ClusterManager.simplify_path_with_intermediates(
                                    path, all_candidate_funcs)
                                
                                if simplified:
                                    graph_paths.append(simplified)
                                    root_nodes.add(simplified[0])
                                    # Update intermediate paths map
                                    intermediate_paths_map.update(path_intermediates)

            if not graph_paths or not root_nodes:
                log("No valid paths found for clustering")
                # Restore previous state
                self.clusters = current_clusters
                self.cluster_analysis = current_analysis
                return

            # Create clusters
            log(f"Creating clusters from {len(graph_paths)} paths with {len(root_nodes)} root nodes")
            self.clusters = ClusterManager.decompose_into_clusters(
                graph_paths, 
                intermediate_paths_map,
                root_nodes,
                self.artifact_functions
            )
            
            # Setup and run cluster analysis
            try:
                self.cluster_analysis = ClusterAnalyzer.analyze_clusters(self.clusters, self)
                # self.cluster_analysis = ClusterAnalyzer.populate_dummy_cluster_analysis(self.clusters)
                if not self.cluster_analysis:  # Empty results usually means network issue
                    log(f"No analysis results obtained - likely network connectivity issue")
                    self.clusters = current_clusters
                    self.cluster_analysis = current_analysis
                    return
                    
                log(f"Generated analysis for {len(self.cluster_analysis.get('clusters', {}))} clusters")
                
            except Exception as e:
                log(f"Error analyzing clusters: {str(e)}")
                # Restore previous state
                self.clusters = current_clusters
                self.cluster_analysis = current_analysis
                
        except Exception as e:
            log(f"Error in cluster analysis: {str(e)}")
            # Restore previous state
            self.clusters = current_clusters
            self.cluster_analysis = current_analysis

    def generate_list_of_non_excluded_functions(self) -> None:
        """
        Get set of all functions that have any non-excluded artifacts.
        
        Returns:
            Set[int]: Set of function addresses with non-excluded artifacts
        """
        self.artifact_functions = set()
        
        for func_ea, xrefs in self.global_xrefs.items():
            direct_xrefs = xrefs[self.DIRECT_XREFS]
            
            # Check each xref type for non-excluded artifacts
            for xref_type in ('libs', 'imports', 'strings', 'capa'):
                entities = direct_xrefs[xref_type]
                # If any entity is not excluded, include this function
                if any(entity not in self.excluded_entities for entity in entities):
                    self.artifact_functions.add(func_ea)
                    break 

    def cluster_all_non_excluded(self) -> None:
        """
        Cluster all non-excluded artifacts and run analysis.
        Now includes cluster merging after initial analysis.
        """
        try:
            if not self.artifact_functions:
                log("No functions with non-excluded artifacts found")
                return
            
            if not self.llm_lookups:
                log("LLM lookups disabled - skipping cluster analysis")
                return

            log(f"Found {len(self.artifact_functions)} functions with non-excluded artifacts")
                
            # Get all entities referenced by these functions
            entities_to_cluster = set()
            for func_ea in self.artifact_functions:
                try:
                    xrefs = self.global_xrefs[func_ea]
                    direct_xrefs = xrefs[self.DIRECT_XREFS]
                    
                    # Get entity indices for each type of xref
                    for xref_type in ('libs', 'imports', 'strings', 'capa'):
                        entities = direct_xrefs[xref_type]
                        # Add non-excluded entities
                        entities_to_cluster.update(e for e in entities 
                                                if e not in self.excluded_entities)
                        
                except KeyError as e:
                    log(f"KeyError processing function 0x{func_ea:x}: {str(e)}")
                except Exception as e:
                    log(f"Error processing function 0x{func_ea:x}: {str(e)}")
            
            log(f"Found {len(entities_to_cluster)} interesting entities")
            
            # Run cluster analysis
            log("Running cluster analysis...")
            self.analyze_clusters(entities_to_cluster)
            self.save_analysis()
                
        except Exception as e:
            log(f"Error in cluster_all_non_excluded: {str(e)}")

    def add_missing_intermediate_nodes(self, clusters: List["FunctionalCluster"], paths: Dict[int, Dict[int, List[List[int]]]]) -> None:
        """
        Add missing intermediate nodes between clusters and their child clusters.
        
        Handles both direct cluster-to-cluster connections and cluster-to-subcluster connections.
        Updates cluster nodes and edges to include intermediate nodes found in paths.
        
        Args:
            clusters: List of clusters to process
            paths: Dictionary mapping entry points to path lists

        Example:
            If cluster A has edge 0x1000 -> Cluster B (root: 0x3000), and paths show:
            0x1000 -> 0x1500 -> 0x2000 -> 0x3000
            
            This will add 0x1500 and 0x2000 to cluster A's nodes and adjust edges to be:
            0x1000 -> 0x1500 -> 0x2000 -> Cluster B
        """
        def get_intermediates(start_node: int, end_node: int, paths_dict: Dict[int, Dict[int, List[List[int]]]]) -> Set[int]:
            """
            Find intermediate nodes from shortest path between two nodes.
            
            Args:
                start_node: Source node address
                end_node: Target node address
                paths_dict: Dictionary containing all paths
                
            Returns:
                Set of intermediate node addresses from shortest path
            """
            shortest_path_length = float('inf')
            shortest_path_intermediates = set()

            for ep in paths_dict:
                for func_paths in paths_dict[ep].values():
                    for path in func_paths:
                        try:
                            start_idx = path.index(start_node)
                            end_idx = path.index(end_node)
                            if start_idx < end_idx:
                                # Calculate path length between nodes
                                path_segment = path[start_idx:end_idx + 1]
                                path_length = len(path_segment)
                                
                                # If this is a shorter path, use its intermediates
                                if path_length < shortest_path_length:
                                    shortest_path_length = path_length
                                    shortest_path_intermediates = set(path[start_idx + 1:end_idx])
                        except ValueError:
                            continue
                            
            return shortest_path_intermediates

        def process_cluster(cluster: "FunctionalCluster") -> None:
            """Process a cluster and its subclusters recursively."""
            # Track edges to be added and removed
            edges_to_add = []
            edges_to_remove = []
            
            # First check cluster's direct edges to other clusters
            for source, target in cluster.edges:
                # Check if target is a reference to another cluster
                if target in cluster.cluster_refs:
                    target_cluster_id = cluster.cluster_refs[target]
                    # Use view's find_cluster_by_id implementation
                    target_cluster = self.find_cluster_by_id(target_cluster_id)
                    if target_cluster:
                        # Find intermediates between source and target cluster's root
                        intermediates = get_intermediates(source, target_cluster.root_node, paths)
                        if intermediates:
                            # Remove original edge
                            edges_to_remove.append((source, target))
                            
                            # Add intermediate nodes to cluster
                            cluster.nodes.update(intermediates)
                            
                            # Create new edge chain
                            sorted_intermediates = sort_nodes_by_path(
                                [source] + list(intermediates) + [target], 
                                paths
                            )
                            
                            # Add new edges through intermediates
                            for i in range(len(sorted_intermediates) - 1):
                                curr_node = sorted_intermediates[i]
                                next_node = sorted_intermediates[i + 1]
                                # If this is the last edge, point to cluster reference
                                if next_node == target_cluster.root_node:
                                    edges_to_add.append((curr_node, target))
                                else:
                                    edges_to_add.append((curr_node, next_node))
            
            # Apply edge changes
            for edge in edges_to_remove:
                if edge in cluster.edges:
                    cluster.edges.remove(edge)
            cluster.edges.extend(edges_to_add)
            
            # Process subclusters
            for subcluster in cluster.subclusters:
                process_cluster(subcluster)

        def sort_nodes_by_path(nodes: List[int], paths_dict: Dict[int, Dict[int, List[List[int]]]]) -> List[int]:
            """Sort nodes according to their order in paths."""
            for ep in paths_dict:
                for func_paths in paths_dict[ep].values():
                    for path in func_paths:
                        # Get indices of all nodes that appear in this path
                        indices = []
                        for node in nodes:
                            try:
                                idx = path.index(node)
                                indices.append((idx, node))
                            except ValueError:
                                continue
                                
                        # If we found all nodes in this path, return them in path order
                        if len(indices) == len(nodes):
                            return [node for _, node in sorted(indices)]
            return nodes  # Fallback to original order if no complete path found

        # Process all clusters
        for cluster in clusters:
            process_cluster(cluster)
    
    def get_color_tags(self, func_ea: int, table_name: str) -> Union[int, Dict[int, List[int]]]:
        """
        Retrieve color tags for a given function and table name.

        Args:
            func_ea (int): The address of the function.
            table_name (str): The name of the table.

        Returns:
            Union[int, Dict[int, List[int]]]: Color tag or a dictionary of color tags.
        """
        if table_name in self.color_tags:
            return self.color_tags[table_name]

        tag_index = {}

        # Retrieve the dictionaries for each reference type
        lib_ea = self.global_xrefs[func_ea][self.DIRECT_XREFS]['libs_ea']
        imp_ea = self.global_xrefs[func_ea][self.DIRECT_XREFS]['imports_ea']
        str_ea = self.global_xrefs[func_ea][self.DIRECT_XREFS]['strings_ea']
        capa_ea = self.global_xrefs[func_ea][self.DIRECT_XREFS]['capa_ea']

        # if enabled, compute counts excluding excluded entities
        if self.settings["enable_exclusions"]:
            lib_refs_count = len(lib_ea.keys() - self.excluded_entities)
            imp_refs_count = len(imp_ea.keys() - self.excluded_entities)
            str_refs_count = len(str_ea.keys() - self.excluded_entities)
            capa_refs_count = len(capa_ea.keys() - self.excluded_entities)
        else:
            lib_refs_count = len(lib_ea)
            imp_refs_count = len(imp_ea)
            str_refs_count = len(str_ea)
            capa_refs_count = len(capa_ea)

        # Calculate index ranges
        lib_refs_index_end = lib_refs_count + 2
        imp_refs_index_end = lib_refs_index_end + imp_refs_count
        str_refs_index_end = imp_refs_index_end + str_refs_count
        capa_refs_index_end = str_refs_index_end + capa_refs_count

        # Assign color tags to index ranges
        tag_index[ida_lines.SCOLOR_DEMNAME] = [2, lib_refs_index_end]
        tag_index[ida_lines.SCOLOR_IMPNAME] = [lib_refs_index_end, imp_refs_index_end]
        tag_index[ida_lines.SCOLOR_DSTR] = [imp_refs_index_end, str_refs_index_end]
        tag_index[ida_lines.SCOLOR_CODNAME] = [str_refs_index_end, capa_refs_index_end]
        return tag_index

    def load_analysis(self) -> None:
        """
        Load existing analysis data or perform fresh analysis.
        
        Attempts to load cached analysis from gzip file, verifies consistency
        with current IDB, and triggers new analysis if needed. Handles image
        base synchronization and exclusions application.
        
        Side Effects:
            - Updates all internal analysis structures
            - May trigger full reanalysis if cache missing or invalid
            - Synchronizes image base if needed
            - Applies current exclusions settings
        """

        idaapi.show_wait_box("HIDECANCEL\nStarting analysis...")
        start_time: float = time()
        analysis_file_path = self.settings["paths"]["analysis"]

        if os.path.exists(analysis_file_path):
            log('Loading existing analysis from: %s' % analysis_file_path)
            with gzip.open(analysis_file_path, 'rb') as infile:
                master_struct = pickle.load(infile)
                self.image_base = master_struct['image_base']
                self.lang = master_struct['lang']
                self.global_xrefs = master_struct['global_xrefs']
                self.string_index_cache = master_struct['string_index_cache']
                self.caller_xrefs_cache = master_struct['caller_xrefs_cache']
                self.paths = master_struct['paths']
                self.table_data = master_struct['table_data']
                self.entities = master_struct['entities']
                self.reverse_entity_lookup_index = master_struct['reverse_entity_lookup_index']
                self.entity_xrefs = master_struct['entity_xrefs']
                self.graph_cache = master_struct['graph_cache']
                self.leaf_funcs = master_struct['leaf_funcs']
                self.api_trace_data = master_struct.get('api_trace_data', {})
                self.interesting_artifacts = master_struct.get('interesting_artifacts', set())
                self.clusters = master_struct.get('clusters', [])
                self.cluster_analysis = master_struct.get('cluster_analysis', {})
            
            self.sync_image_base(False)
            self.process_exclusions()

            if self.settings['enable_exclusions']:
                self.clear_affected_function_tables()

            if not self.current_analysis_ep:
                self.current_analysis_ep = self.lang.entry_point

            if self.current_analysis_ep in self.paths:
                return

            if self.is_node_in_existing_paths(self.current_analysis_ep):
                return

            self.run_secondary_analysis()
            self.clear_affected_graph_cache()
            self.save_analysis()
        elif not self.check_required_files():
            idaapi.hide_wait_box()
            return
        else:
            try:
                self.run_full_analysis()
                self.save_analysis()
            except Exception as err:
                log('Error running full analysis {err}')
        
        log_elapsed_time('Analysis Time', start_time)

    def save_analysis(self) -> None:
        """
        Save current analysis state to file.
        
        Serializes all analysis data to a gzipped pickle file for later reuse.
        Includes all cross-references, paths, entities, and analysis results.
        
        Note:
            Creates master_struct containing:
            - image_base: Current image base address
            - lang: Language analyzer state
            - global_xrefs: All cross-reference data
            - string_index_cache: String lookup cache
            - caller_xrefs_cache: Cross-reference cache
            - paths: All analyzed paths
            - table_data: Function context tables
            - entities: All identified entities
            - reverse_entity_lookup_index: Entity lookup cache
            - entity_xrefs: Entity cross-references
            - graph_cache: Cached graph layouts
            - leaf_funcs: Identified leaf functions
            - api_trace_data: API trace information
            - interesting_artifacts: LLM-identified interesting items
        """

        idaapi.hide_wait_box()
        analysis_file_path = self.settings['paths']['analysis']
        log('Saving analysis to: %s' % analysis_file_path)
        with gzip.open(analysis_file_path, 'wb') as outfile:
            master_struct = {
                'image_base': self.image_base,
                'lang': self.lang,
                'global_xrefs': self.global_xrefs,
                'string_index_cache': self.string_index_cache,
                'caller_xrefs_cache': self.caller_xrefs_cache,
                'paths': self.paths,
                'table_data': self.table_data,
                'entities': self.entities,
                'reverse_entity_lookup_index': self.reverse_entity_lookup_index,
                'entity_xrefs': self.entity_xrefs,
                'graph_cache': self.graph_cache,
                'leaf_funcs': self.leaf_funcs,
                'api_trace_data': self.api_trace_data,
                'interesting_artifacts': self.interesting_artifacts,
                'clusters': self.clusters,
                'cluster_analysis': self.cluster_analysis
            }
            pickle.dump(master_struct, outfile)

    def load_categories(self) -> None:
        """
        Load category data for analysis.

        This method loads or creates category data used for classifying
        various elements in the analysis.
        """
        catfile_name_initial = 'xrefer_categories_initial.json'
        xrefer_user_catfile_path = self.settings['paths']['categories']
        xrefer_user_dir_path = os.path.dirname(xrefer_user_catfile_path)
        xrefer_plugin_catfile_path = os.path.join(self.plugin_subdir_path, 'data', catfile_name_initial)

        if not os.path.exists(xrefer_user_catfile_path):
            if os.path.exists(xrefer_plugin_catfile_path):
                if not os.path.exists(xrefer_user_dir_path):
                    os.makedirs(xrefer_user_dir_path)
                log(f'Copying existing categories file to xrefer user dir :: {xrefer_user_catfile_path}')
                shutil.copy(xrefer_plugin_catfile_path, xrefer_user_catfile_path)

        if os.path.exists(xrefer_user_catfile_path):
            log(f'Loading existing categories file from :: {xrefer_user_catfile_path}')
            with open(xrefer_user_catfile_path, 'r') as infile:
                self.categories = json.load(infile)
        else:
            self.categories = {'apis': {}, 'libs': {}, 'api_categories': [], 'lib_categories': []}

    def save_categories(self) -> None:
        """
        Save category data to a file.

        This method saves the current category data to a JSON file.
        """
        xrefer_user_catfile_path = self.settings['paths']['categories']
        xrefer_user_dir_path = os.path.dirname(xrefer_user_catfile_path)

        if not os.path.exists(xrefer_user_dir_path):
            os.makedirs(xrefer_user_dir_path)

        log(f'Dumping categories to :: {xrefer_user_catfile_path}')

        try:
            with open(xrefer_user_catfile_path, 'w') as outfile:
                json.dump(self.categories, outfile)
        except Exception as e:
            log(f'Failed to write {xrefer_user_catfile_path}: {str(e)}')

    def configure_llm_and_lookups(self) -> None:
        """
        Configure LLM-based lookups and settings.
        
        Sets up configuration for Git and LLM-based analysis based on
        current settings. Initializes appropriate LLM models and configures
        both categorizer and artifact analyzer.
        
        Side Effects:
            - Updates self.git_lookups and self.llm_lookups flags
            - Configures LLM model settings if enabled
            - Sets up model configurations for different analysis types
            
        Raises:
            ValueError: If configured LLM provider is not supported
        """
        try:
            self.git_lookups = self.settings['git_lookups']
            self.llm_lookups = self.settings['llm_lookups']
            
            if self.llm_lookups:
                llm_origin = self.settings['llm_origin']
                model_name = self.settings['llm_model']
                api_key = self.settings['api_key']
                model_type = None
                
                if llm_origin == 'openai':
                    model_type = ModelType.OPENAI
                elif llm_origin == 'google':
                    model_type = ModelType.GOOGLE
                else:
                    raise ValueError(f"Unsupported LLM origin: {llm_origin}")
                
                log(f'Setting LLM model to: {model_name}')
                config_1 = ModelConfig(model_type, model_name, api_key, ignore_token_limit=True)
                config_2 = ModelConfig(model_type, model_name, api_key)
                ArtifactAnalyzer.set_model_config(config_1)
                ClusterAnalyzer.set_model_config(config_1)
                Categorizer.set_model_config(config_2)       
            
        except Exception as err:
            log(f'Error loading config: {str(err)}')

    def sync_image_base(self, manual: bool = True) -> None:
        """
        Synchronize analysis with current IDB image base.
        
        Updates all address-based data structures when binary image base
        changes. Critical for maintaining analysis validity after rebasing.
        
        Args:
            manual (bool): Whether sync was manually triggered
            
        Side Effects:
            - Updates all address-based data structures
            - Clears graph cache
            - Updates global cross-references
            - Updates caller references cache
            - Updates analysis paths
            - Updates entity cross-references
            - Updates leaf functions
            - Updates API trace data
            - Updates cluster data
            - Repopulates function context tables
            - Saves updated analysis state
        """
        image_base = idaapi.get_imagebase()
        if image_base == self.image_base:
            if manual:
                log(f'Imagebase already synced with IDB imagebase: 0x{image_base:x}')
            return

        msg = f'Image base change detected, new base: 0x{image_base:x}'
        idaapi.show_wait_box(f'HIDECANCEL\n{msg}')
        log(msg)

        delta = image_base - self.image_base
        self.image_base = image_base

        log('Resetting graph cache')
        self.graph_cache = {}

        log('Updating global xrefs')
        self.sync_image_base_gx(delta)
        log('Updating caller xrefs cache')
        self.sync_image_base_cx(delta)
        log('Updating paths')
        self.sync_image_base_p(delta)
        log('Updating entity xrefs')
        self.sync_image_base_ex(delta)
        log('Updating leaf functions')
        self.sync_image_base_lf(delta)
        log('Updating api trace data')
        self.sync_image_base_at(delta)
        log('Updating cluster addresses')
        self.sync_image_base_cs(delta)
        self.lang.entry_point += delta

        log('Image-base synced, re-populating context tables for all functions...')
        self.table_data = {}
        self._populate_function_context_tables()
        idaapi.hide_wait_box()
        self.save_analysis()

    def sync_image_base_gx(self, delta: int) -> None:
        """
        Synchronize the image base for global cross-references.

        Args:
            delta (int): The change in the image base address.
        """
        for func_ea in self.global_xrefs:
            for xref_type in self.INDIRECT_XREFS, self.DIRECT_XREFS:
                # Update api_trace set
                api_trace_set = self.global_xrefs[func_ea][xref_type]['api_trace']
                self.global_xrefs[func_ea][xref_type]['api_trace'] = {addr + delta for addr in api_trace_set}
                
                # Update other address types
                for addr_type in 'libs_ea', 'imports_ea', 'strings_ea', 'capa_ea', 'api_trace_ea':
                    for e_index in self.global_xrefs[func_ea][xref_type][addr_type]:
                        addr_set = self.global_xrefs[func_ea][xref_type][addr_type][e_index]
                        self.global_xrefs[func_ea][xref_type][addr_type][e_index] = {addr + delta for addr in addr_set}

        self.global_xrefs = self.sync_image_base_dictkeys(self.global_xrefs, delta)

    def sync_image_base_cx(self, delta: int) -> None:
        """
        Synchronize the image base for caller cross-references cache.

        Args:
            delta (int): The change in the image base address.
        """
        for func_ea in self.caller_xrefs_cache:
            for ref_frm in self.caller_xrefs_cache[func_ea]:
                addr_set = self.caller_xrefs_cache[func_ea][ref_frm]
                self.caller_xrefs_cache[func_ea][ref_frm] = {addr + delta for addr in addr_set}

        for func_ea in self.caller_xrefs_cache:
            self.caller_xrefs_cache[func_ea] = self.sync_image_base_dictkeys(self.caller_xrefs_cache[func_ea], delta)

        self.caller_xrefs_cache = self.sync_image_base_dictkeys(self.caller_xrefs_cache, delta)

    def sync_image_base_p(self, delta: int) -> None:
        """
        Synchronize the image base for paths.

        Args:
            delta (int): The change in the image base address.
        """
        for ep in self.paths:
            for func_ea in self.paths[ep]:
                for path in self.paths[ep][func_ea]:
                    path[:] = [addr + delta for addr in path]

        for ep in self.paths:
            self.paths[ep] = self.sync_image_base_dictkeys(self.paths[ep], delta)

        self.paths = self.sync_image_base_dictkeys(self.paths, delta)

    def sync_image_base_ex(self, delta: int) -> None:
        """
        Synchronize the image base for entity cross-references.

        Args:
            delta (int): The change in the image base address.
        """
        for e_index in self.entity_xrefs:
            addr_set = self.entity_xrefs[e_index]
            self.entity_xrefs[e_index] = {addr + delta for addr in addr_set}

    def sync_image_base_lf(self, delta: int) -> None:
        """
        Synchronize the image base for leaf functions.

        Args:
            delta (int): The change in the image base address.
        """
        self.leaf_funcs = {func_ea + delta for func_ea in self.leaf_funcs}

    def sync_image_base_at(self, delta: int) -> None:
        """
        Synchronize the api_trace_data with the new image base.

        Args:
            delta (int): The difference between the new and old image base.
        """
        updated_api_trace_data = {}
        for func_ea, api_calls in self.api_trace_data.items():
            new_func_ea = func_ea + delta
            updated_api_trace_data[new_func_ea] = api_calls

            # Update addresses within the API call data
            for api_name, calls in api_calls.items():
                for call in calls:
                    if 'call_addr' in call:
                        call['call_addr'] += delta
                    if 'return_addr' in call:
                        call['return_addr'] += delta

        self.api_trace_data = updated_api_trace_data

    def sync_image_base_cs(self, delta: int) -> None:
        """
        Synchronize all cluster addresses with the new image base.
        
        Updates all address references in clusters including:
        - Root node addresses
        - Node set members
        - Edge source/target pairs
        - Intermediate path addresses
        - Cluster reference mappings
        - Subcluster addresses recursively
        
        Args:
            delta (int): The difference between new and old image base
        """
        if not self.clusters:
            return
            
        def rebase_cluster(cluster: FunctionalCluster) -> None:
            """
            Rebase all addresses within a single cluster.
            
            Args:
                cluster: FunctionalCluster whose addresses need rebasing
            """
            # Rebase root node
            cluster.root_node += delta
            
            # Rebase all nodes
            cluster.nodes = {node + delta for node in cluster.nodes}
            
            # Rebase edges
            cluster.edges = [(source + delta, target + delta) 
                            for source, target in cluster.edges]
            
            # Rebase intermediate paths
            new_paths = {}
            for (source, target), paths in cluster.intermediate_paths.items():
                new_key = (source + delta, target + delta)
                new_paths[new_key] = {
                    tuple(addr + delta for addr in path)
                    for path in paths
                }
            cluster.intermediate_paths = new_paths
            
            # Rebase cluster_refs mapping
            new_refs = {}
            for node, cluster_id in cluster.cluster_refs.items():
                new_refs[node + delta] = cluster_id
            cluster.cluster_refs = new_refs
            
            # Recursively rebase subclusters
            for subcluster in cluster.subclusters:
                rebase_cluster(subcluster)
        
        # Rebase all clusters
        for cluster in self.clusters:
            rebase_cluster(cluster)

    def sync_image_base_dictkeys(self, addrs: Dict[int, Any], delta: int) -> Dict[int, Any]:
        """
        Synchronize the image base for dictionary keys.

        Args:
            addrs (Dict[int, Any]): The dictionary of addresses to update.
            delta (int): The change in the image base address.

        Returns:
            Dict[int, Any]: The updated dictionary with synchronized addresses.
        """
        updated_addrs = {}
        for addr, value in addrs.items():
            updated_addrs[addr + delta] = value
        return updated_addrs

    def select_optimal_node_for_boundary_scan(self, scan_entities: Set[int], ep: int) -> int:
        """
        Select best node for performing boundary scan.
        
        Chooses the entity that will provide most efficient boundary scan
        by analyzing path counts and cross-reference patterns.
        
        Args:
            scan_entities (Set[int]): Set of entity indices to consider
            ep (int): Entry point to analyze paths from
            
        Returns:
            int: Index of selected node with minimum path count
            
        Note:
            Selects node that appears in fewest paths to minimize
            the number of paths that need to be analyzed during scan.
        """
        minimum_path_count = float('inf')
        selected_node = None

        for e_index in scan_entities:
            path_count = 0
            for xref in self.entity_xrefs[e_index]:
                func = idaapi.get_func(xref)

                if not func:
                    continue                # there will be no function present at unloaded/encrypted regions of the binary, while api calls from traces might actually be present

                try:
                    path_count += len(self.paths[ep][func.start_ea])
                except KeyError:
                    pass

            if path_count < minimum_path_count:
                selected_node = e_index
                minimum_path_count = path_count

        return selected_node

    def scan_for_boundary_methods(self, scan_entities: Set[int], e_index: int, ep: int) -> List[int]:
        """
        Scan for boundary methods containing all specified entities.
        
        Finds functions that contain all the specified entities by analyzing
        paths from entry point to each cross-reference.
        
        Args:
            scan_entities (Set[int]): Set of entity indices that must be present
            e_index (int): Index of entity to use as starting point
            ep (int): Entry point to analyze paths from
            
        Returns:
            List[int]: List of function addresses that contain all specified entities
            
        Note:
            Uses e_index as optimization point - starts from cross-references to
            this entity and checks if other entities are present along paths.
        """
        boundary_methods = set()

        for xref in self.entity_xrefs[e_index]:
            func = idaapi.get_func(xref)

            if not func:
                continue            # there will be no function present at unloaded/encrypted regions of the binary, while api calls from traces might actually be present

            if func.start_ea not in self.paths[ep]:
                continue

            for path in self.paths[ep][func.start_ea]:
                for node_ea in reversed(path):
                    combined_xrefs = self.global_xrefs[node_ea][self.COMBINED_XREFS]
                    if scan_entities.issubset(combined_xrefs):
                        boundary_methods.add(node_ea)
                        break

        return list(boundary_methods)

    def run_boundary_scan(self, scan_entities: Set[int]) -> List[int]:
        """
        Run a boundary scan for a given set of entities across all entry points.

        Args:
            scan_entities (Set[int]): The set of entities to scan.

        Returns:
            List[int]: A consolidated list of boundary method addresses from all entry points.
        """
        if not len(scan_entities):
            return []

        all_boundary_methods = set()
        for ep in self.paths:
            e_index = self.select_optimal_node_for_boundary_scan(scan_entities, ep)
            boundary_methods = self.scan_for_boundary_methods(scan_entities, e_index, ep)
            all_boundary_methods.update(boundary_methods)

        return list(all_boundary_methods)

    def generate_entity_xrefs_listing(self, e_index: int) -> List[List[Union[int, str]]]:
        """
        Generate a listing of cross-references for a given entity index.
        Now considers both path reachability and indirect xrefs for orphan status.

        Args:
            e_index (int): The index of the entity.

        Returns:
            List[List[Union[int, str]]]: A list of cross-reference items.
        """
        xrefs = self.entity_xrefs[e_index]
        xref_items = []

        for xref in xrefs:
            xref_func = idaapi.get_func(xref)

            if not xref_func:  # Skip if no function (e.g., unloaded/encrypted regions)
                continue

            xref_func_ea = xref_func.start_ea
            orphan = 'Yes' if self.is_orphan_function(xref_func_ea) else 'No'
            xref_item = [xref_func.start_ea, orphan, idc.get_func_name(xref_func_ea)]
            if xref_item not in xref_items:
                xref_items.append(xref_item)

        xref_items.sort(key=lambda x: x[1])  # Sort by orphan status
        xref_items = list(zip(*xref_items))
        return xref_items
    
    def get_apis_for_function(self, func_ea: int) -> List[str]:
        """
        Get all direct APIs from a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            List of API name strings
        """
        apis = []
        
        # Get direct imports
        try:
            for e_index in self.global_xrefs[func_ea][self.DIRECT_XREFS]['imports']:
                if self.settings["enable_exclusions"] and e_index in self.excluded_entities:
                    continue
                apis.append(self.entities[e_index][1])  # entity[1] contains the API name
        except KeyError:
            pass
        
        # Get direct APIs from trace
        if func_ea in self.api_trace_data:
            for api_name in self.api_trace_data[func_ea]:
                if '.' not in api_name:
                    continue
                # Check if API is excluded
                if self.settings["enable_exclusions"]:
                    api_suffix = api_name.split('.')[-1].lower()
                    if api_suffix in (name.lower() for name in self.exclusions['apis']):
                        continue
                apis.append(api_name)
                
        return apis

    def get_libs_for_function(self, func_ea: int) -> List[str]:
        """
        Get all library references from a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            List of library name strings
        """
        libs = []
        try:
            for e_index in self.global_xrefs[func_ea][self.DIRECT_XREFS]['libs']:
                if self.settings["enable_exclusions"] and e_index in self.excluded_entities:
                    continue
                libs.append(self.entities[e_index][1])  # entity[1] contains the lib name
        except KeyError:
            pass
        return libs

    def get_strings_for_function(self, func_ea: int) -> List[str]:
        """
        Get all strings referenced by a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            List of string values
        """
        strings = []
        try:
            for e_index in self.global_xrefs[func_ea][self.DIRECT_XREFS]['strings']:
                if self.settings["enable_exclusions"] and e_index in self.excluded_entities:
                    continue
                strings.append(self.entities[e_index][6])  # entity[6] contains the full string value
        except KeyError:
            pass
        return strings

    def get_capa_for_function(self, func_ea: int) -> List[str]:
        """
        Get all CAPA rule matches for a function.
        
        Args:
            func_ea: Function address
            
        Returns:
            List of CAPA rule names
        """
        capa_matches = []
        try:
            for e_index in self.global_xrefs[func_ea][self.DIRECT_XREFS]['capa']:
                if self.settings["enable_exclusions"] and e_index in self.excluded_entities:
                    continue
                capa_matches.append(self.entities[e_index][1])  # entity[1] contains the CAPA rule name
        except KeyError:
            pass
        return capa_matches

    def get_direct_calls(self, api_name: str, func_ea: int, colorized: bool = True) -> Tuple[str, ...]:
        """
        Retrieve direct API calls for a specific API within a given function.

        This method searches for all instances where the specified API is directly
        called within the function identified by func_ea.

        Args:
            api_name (str): The full name of the API to search for, including the module name
                        (e.g., "kernel32.CreateFileW").
            func_ea (int): The effective address (EA) of the function to search within.
            colorized (bool): Whether to return color-coded call strings (True) or 
                            plain call strings (False). Default is True for backward compatibility.

        Returns:
            Tuple[Tuple[str, int], ...]: A tuple of tuples, where each inner tuple contains:
                - str: The API call string formatted as "(<arg1>, <arg2>, ...) = <return_value>"
                - int: Number of times this exact call signature was seen

        Note:
            If colorized=True, the returned call strings will contain IDA color codes.
            If colorized=False, the call strings will have identical formatting but no color codes.
        """
        func_data = self.api_trace_data.get(func_ea, {})
        api_calls = func_data.get(api_name, [])

        if colorized:
            return tuple((call['call_str'], call['count']) for call in api_calls)
        else:
            # Reconstruct call strings without color codes
            plain_calls = []
            for call in api_calls:
                args_str = f"({', '.join(call['args'])})"
                return_str = str(call['return_value'])
                plain_call = f"{args_str} = {return_str}"
                plain_calls.append((plain_call, call['count']))
            return tuple(plain_calls)

    def get_indirect_calls(self, api_name: str, func_ea: int) -> Tuple[str, ...]:
        """
        Retrieve indirect API calls for a specific API made by functions called from the given function.

        This method searches for all instances where the specified API is called by functions
        that are indirectly referenced (called) by the function identified by func_ea.

        Args:
            api_name (str): The full name of the API to search for, including the module name
                            (e.g., "kernel32.CreateFileW").
            func_ea (int): The effective address (EA) of the function to start the search from.

        Returns:
            Tuple[str, ...]: A tuple of strings, where each string represents a single API call.
                             Each call is formatted as "((<arg1>, <arg2>, ...) = <return_value>)".
                             The double parentheses distinguish indirect calls from direct calls.
                             Returns an empty tuple if no calls are found.

        Note:
            This function relies on self.global_xrefs and self.api_trace_data being properly
            populated during the analysis process.
        """
        result = set()

        indirect_xrefs = self.global_xrefs.get(func_ea, {}).get(self.INDIRECT_XREFS, {})
        indirect_func_addresses = indirect_xrefs.get('api_trace', set())

        for indirect_func_ea in indirect_func_addresses:
            api_calls = self.api_trace_data[indirect_func_ea].get(api_name, [])
            for call in api_calls:
                result.add((call['call_str'], call['count']))

        return tuple(result)

    def _gather_sorted_function_api_calls(self, func_ea):
        if func_ea not in self.api_trace_data:
            return []

        function_api_calls = []
        for api_name, api_calls in self.api_trace_data[func_ea].items():
            api_name = ida_lines.COLSTR(api_name.split('.')[1], ida_lines.SCOLOR_IMPNAME)

            for call in api_calls:
                call_addr = ida_lines.COLSTR(f'0x{call["call_addr"]:x}', ida_lines.SCOLOR_LIBNAME)
                function_api_calls.append((call['index'],  f'{call_addr}: {api_name}{call["call_str"]} x {call["count"]}'))

        return function_api_calls

    def gather_sorted_function_api_calls(self, func_ea):
        """
        Gather and sort all "call_str" for direct API calls of a given function.

        :param func_ea: The address of the function
        :return: A list of sorted "call_str" for direct API calls
        """
        function_api_calls = self._gather_sorted_function_api_calls(func_ea)
        function_api_calls.sort(key=itemgetter(0))
        return [call[1] for call in function_api_calls]

    def gather_sorted_path_api_calls(self, func_ea):
        """
        Gather and sort all "call_str" for indirect API calls of a given function.

        :param func_ea: The address of the function
        :return: A list of sorted "call_str" for indirect API calls
        """
        path_api_calls = []

        # Get all functions called indirectly by func_ea
        indirect_xrefs = self.global_xrefs.get(func_ea, {}).get(self.INDIRECT_XREFS, {})
        indirect_func_addresses = indirect_xrefs.get('api_trace', set())

        # Gather API calls from these indirect functions
        for indirect_func_ea in indirect_func_addresses:
            if indirect_func_ea in self.api_trace_data:
                for api_name, api_calls in self.api_trace_data[indirect_func_ea].items():
                    api_name = ida_lines.COLSTR(api_name.split('.')[1], ida_lines.SCOLOR_IMPNAME)

                    for call in api_calls:
                        call_addr = ida_lines.COLSTR(f'0x{call["call_addr"]:x}', ida_lines.SCOLOR_LIBNAME)
                        path_api_calls.append((call['index'], f'{call_addr}: {api_name}{call["call_str"]} x {call["count"]}'))

        function_api_calls = self._gather_sorted_function_api_calls(func_ea)
        path_api_calls.extend(function_api_calls)
        path_api_calls.sort(key=itemgetter(0))
        return [call[1] for call in path_api_calls]

    def gather_sorted_full_api_calls(self):
        all_calls = []

        # Iterate through all functions and their API calls
        for func_calls in self.api_trace_data.values():
            for api_name, api_calls in func_calls.items():
                api_name = ida_lines.COLSTR(api_name.split('.')[1], ida_lines.SCOLOR_IMPNAME)

                for call in api_calls:
                    call_addr = ida_lines.COLSTR(f'0x{call["call_addr"]:x}', ida_lines.SCOLOR_LIBNAME)
                    all_calls.append((call['index'], f'{call_addr}: {api_name}{call["call_str"]} x {call["count"]}'))

        # Sort the list based on the index
        all_calls.sort(key=itemgetter(0))
        return [call[1] for call in all_calls]

    def _has_direct_calls(self, func_ea: int, api_name: str) -> bool:
        """Check if a function has direct calls for a specific API."""
        return bool(self.api_trace_data.get(func_ea, {}).get(api_name, []))

    def _has_indirect_calls(self, func_ea: int, api_name: str) -> bool:
        """Check if a function has indirect calls for a specific API."""
        global_xrefs = self.global_xrefs.get(func_ea, {}).get(self.INDIRECT_XREFS, {})
        indirect_func_addresses = global_xrefs.get('api_trace', set())

        for indirect_func_ea in indirect_func_addresses:
            if api_name in self.api_trace_data.get(indirect_func_ea, {}):
                return True
        return False
    
    def clear_affected_function_tables(self) -> None:
        """
        Clear exclusions affected function context tables.
        """
        # Get functions that need updating
        affected_funcs = self.get_functions_with_excluded_items()
        
        if not affected_funcs:
            log("No excluded functions available")
            return
        
        # Delete affected functions' tables
        for func_ea in affected_funcs:
            if func_ea in self.table_data:
                del self.table_data[func_ea]
                
        log(f"Cleared cache for {len(affected_funcs)} function tables")

    def _populate_function_context_tables(self) -> None:
        """
        Populate the function context tables with data.
        """
        for func_ea in self.global_xrefs:
            self.table_data[func_ea] = self.create_sorted_table(func_ea)

    def create_sorted_table(self, func_ea: int) -> Dict[str, Dict[str, Union[List[str], OrderedDict]]]:
        """
        Create a sorted table of cross-references for a function.

        Args:
            func_ea (int): The address of the function.

        Returns:
            Dict[str, Dict[str, Union[List[str], OrderedDict]]]: A dictionary containing the sorted table data.
        """
        table_types = {
            'INDIRECT IMPORT XREFS': 'imports_ea',
            'INDIRECT LIBRARY XREFS': 'libs_ea',
            'INDIRECT STRING XREFS': 'strings_ea',
            'INDIRECT CAPA XREFS': 'capa_ea',
            'DIRECT XREFS': 'direct_xrefs'
        }

        # List of keys that need to be pre-populated with OrderedDict
        prepopulated_keys = ['INDIRECT IMPORT XREFS', 'INDIRECT LIBRARY XREFS']

        # Initialize the table with conditional pre-population for sorting
        sorted_xref_table = {
            key: {'rows': OrderedDict((ct, None) for ct in CATEGORIES)} if key in prepopulated_keys else {'rows': OrderedDict()} 
            for key in table_types
        }

        for table_key, xref_key in table_types.items():
            if table_key.startswith('D'):
                self.process_xref_type(func_ea, None, sorted_xref_table, table_key, self.DIRECT_XREFS)
            else:
                self.process_xref_type(func_ea, xref_key, sorted_xref_table, table_key, self.INDIRECT_XREFS)

        self.finalize_table(func_ea, sorted_xref_table)
        return sorted_xref_table

    def process_xref_type(self, func_ea: int, xref_key: Optional[str],
                          sorted_xref_table: Dict[str, Dict[str, Union[List[str], OrderedDict]]], table_key: str,
                          table_category: int) -> None:
        """
        Process a specific type of cross-reference for a function.

        Args:
            func_ea (int): The address of the function.
            xref_key (Optional[str]): The key for the type of cross-reference.
            sorted_xref_table (Dict[str, Dict[str, Union[List[str], OrderedDict]]]): The dictionary to store the sorted table data.
            table_key (str): The key for the table type.
            table_category (int): The category of the table (DIRECT_XREFS or INDIRECT_XREFS).
        """
        if self.INDIRECT_XREFS == table_category:
            self.process_rows_for_indirect_xrefs(func_ea, xref_key, sorted_xref_table, table_key)
        else:
            for _xref_key in 'libs_ea', 'imports_ea', 'strings_ea', 'capa_ea':
                self.process_rows_for_direct_xrefs(func_ea, _xref_key, sorted_xref_table, table_key)

    def process_rows_for_indirect_xrefs(self, func_ea: int, xref_key: str,
                                        sorted_xref_table: Dict[str, Dict[str, Union[List[str], OrderedDict]]],
                                        table_key: str) -> None:
        """self.DIRECT_XREFS
        Process rows for indirect cross-references.

        Args:
            func_ea (int): The address of the function.
            xref_key (str): The key for the type of cross-reference.
            sorted_xref_table (Dict[str, Dict[str, Union[List[str], OrderedDict]]]): The dictionary to store the sorted table data.
            table_key (str): The key for the table type.
        """
        if xref_key in self.global_xrefs[func_ea][self.INDIRECT_XREFS]:
            xref_data = self.global_xrefs[func_ea][self.INDIRECT_XREFS][xref_key]
            for key, val in xref_data.items():
                if self.settings["enable_exclusions"]:
                    if key in self.excluded_entities:
                        continue

                entity = self.entities[key]
                if entity[2] in (2, 5):  # Import or API Trace
                    has_indirect_calls = self._has_indirect_calls(func_ea, entity[1])
                    prefix = '    → ' if has_indirect_calls else '    '
                    new_row = [f"{prefix}{entity[1]}"]
                else:
                    new_row = [f"    {self.entities[key][1]}"]
                for child_func_ea in val:
                    try:
                        new_row.extend(list(self.caller_xrefs_cache[func_ea][child_func_ea]))
                    except KeyError:
                        pass
                self.update_table(sorted_xref_table, table_key, key, new_row)

    def process_rows_for_direct_xrefs(self, func_ea: int, xref_key: str,
                                      sorted_xref_table: Dict[str, Dict[str, Union[List[str], OrderedDict]]],
                                      table_key: str) -> None:
        """
        Process rows for direct cross-references.

        Args:
            func_ea (int): The address of the function.
            xref_key (str): The key for the type of cross-reference.
            sorted_xref_table (Dict[str, Dict[str, Union[List[str], OrderedDict]]]): The dictionary to store the sorted table data.
            table_key (str): The key for the table type.
        """
        if xref_key in self.global_xrefs[func_ea][self.DIRECT_XREFS]:
            xref_data = self.global_xrefs[func_ea][self.DIRECT_XREFS][xref_key]

            for key, val in xref_data.items():
                if self.settings["enable_exclusions"]:
                    if key in self.excluded_entities:
                        continue

                entity = self.entities[key]
                if entity[2] in (2, 5):  # Import or API Trace
                    has_direct_calls = self._has_direct_calls(func_ea, entity[1])
                    prefix = '→ ' if has_direct_calls else ''
                    new_row = [f"{prefix}{entity[1]}"]
                    new_row.extend(list(val) if val else [])
                    self.update_table(sorted_xref_table, table_key, key, new_row, '-')   # use place holder category for direct xrefs to keep sorting intact
                else:
                    new_row = [entity[1]]
                    new_row.extend(list(val) if val else [])
                    self.update_table(sorted_xref_table, table_key, key, new_row, '-')

    def update_table(self, sorted_xref_table: Dict[str, Dict[str, Union[List[str], OrderedDict]]], table_key: str,
                     entity_key: int, row_data: List[str], category: str=None) -> None:
        """
        Update the sorted table with new row data.

        Args:
            sorted_xref_table (Dict[str, Dict[str, Union[List[str], OrderedDict]]]): The dictionary to store the sorted table data.
            table_key (str): The key for the table type.
            entity_key (int): The key for the entity.
            row_data (List[str]): The row data to add to the table.
        """

        if not category:
            category = self.entities[entity_key][0]
        
        try:
            sorted_xref_table[table_key]['rows'][category].append(row_data)
                
        except (KeyError, AttributeError):
            sorted_xref_table[table_key]['rows'][category] = [row_data]

    def finalize_table(self, func_ea: int,
                       sorted_xref_table: Dict[str, Dict[str, Union[List[str], OrderedDict]]]) -> None:
        """
        Finalize the sorted table by organizing and coloring the table data.

        Args:
            func_ea (int): The address of the function.
            sorted_xref_table (Dict[str, Dict[str, Union[List[str], OrderedDict]]]): The dictionary to store the sorted table data.
        """
        for key in sorted_xref_table:
            if not sorted_xref_table[key]['rows']:
                continue
            
            rows = []
            
            for inner_table_key in list(sorted_xref_table[key]['rows'].keys()):  # Create a list of keys to iterate over
                _rows = sorted_xref_table[key]['rows'][inner_table_key]
                
                if _rows:
                    rows += _rows
                else:
                    sorted_xref_table[key]['rows'].pop(inner_table_key)  # Safely remove the item

            if not rows:
                continue

            colored_table = create_xrefs_table_colored(key, rows, self.get_color_tags(func_ea, key))
            prev_offset = 3
            for inner_table_key in sorted_xref_table[key]['rows']:
                inner_table_length = len(sorted_xref_table[key]['rows'][inner_table_key])
                if inner_table_length:
                    sorted_xref_table[key]['rows'][inner_table_key] = colored_table[
                                                                      prev_offset:prev_offset + inner_table_length]
                    prev_offset += inner_table_length
            sorted_xref_table[key]['heading'] = colored_table[1:3] if sorted_xref_table[key]['rows'] else []

    def run_full_analysis(self) -> None:
        """
        Perform the full analysis, loading configuration and categories, sifting references, and generating context tables.
        """
        if self.table_data:
            return self.table_data

        log('Starting analysis...')
        self.load_categories()
        self.capa_matches = load_capa_json(self.settings['paths']['capa'])
        self.lang = self.get_lang_object()
        self.add_user_xrefs()
        self.create_xref_mapping()
        self.sift_strings()
        self.sift_libs()
        self.sift_capa_matches()
        self.entities = enrich_string_data(self.string_index_cache, self.entities, self.git_lookups)
        self.load_imports()
        self.process_api_trace()
        self.save_categories()
        self.map_refs_to_leaf_functions(self.strings[0] + self.imports + self.lib_refs)
        self.generate_reverse_entity_lookup_index()

        for _tuple in self.strings[1]:
            for xref in _tuple[3]:
                self.mapped_refs.append((xref, _tuple[1], _tuple[2]))

        self.mapped_refs += self.capa_matches
        log('Generating context table data...')

        for ref in self.mapped_refs:
            orig_name = idc.get_func_name(ref[0])
            func_ea = idc.get_name_ea(0, orig_name)
            self.leaf_funcs.add(func_ea)

            entity_index = ref[1]
            ref_addr = ref[0]
            entity_type_key = self.entity_type[ref[2]]
            entity_suffix_key = self.entity_suffix_map[entity_type_key]

            if entity_index not in self.entity_xrefs:
                self.entity_xrefs[entity_index] = set()
            self.entity_xrefs[entity_index].add(ref_addr)

            if func_ea not in self.global_xrefs:
                self.global_xrefs[func_ea] = {
                    self.DIRECT_XREFS: self.init_global_xrefs_template(),
                    self.INDIRECT_XREFS: self.init_global_xrefs_template(),
                    self.COMBINED_XREFS: set()
                }

            direct_xrefs = self.global_xrefs[func_ea][self.DIRECT_XREFS]
            direct_xrefs[entity_type_key].add(entity_index)

            if entity_index not in direct_xrefs[entity_suffix_key]:
                direct_xrefs[entity_suffix_key][entity_index] = set()
            direct_xrefs[entity_suffix_key][entity_index].add(ref_addr)

        if not self.current_analysis_ep:
            self.current_analysis_ep = self.lang.entry_point

        idc.set_func_cmt(self.lang.entry_point, self.lang.ep_annotation, 0)
        self.process_exclusions()
        self.run_secondary_analysis()

    def run_secondary_analysis(self) -> None:
        """
        Run secondary analysis, including generating call paths and propagating cross-reference nodes.
        """
        self.generate_all_simple_call_paths_for_ep()
        iters = 1

        while self.propagate_xref_nodes(iters):
            iters += 1

        self.fix_thunk_xrefs()
        self.populate_xref_addrs()
        self.cluster_all_non_excluded()
        log('Populating function context tables...')
        self._populate_function_context_tables()

    def run_standalone_secondary_analysis(self) -> None:
        """
        Run a standalone secondary analysis for the current entry point.
        """
        if self.current_analysis_ep in self.paths:
            ep_name = idc.get_func_name(self.current_analysis_ep)
            log(f'Entrypoint already analyzed: 0x{self.current_analysis_ep:x} ({ep_name})')
            return

        if self.is_node_in_existing_paths(self.current_analysis_ep):
            return

        idaapi.show_wait_box(f'HIDECANCEL\nStarting Analysis...')
        start_time = time()
        self.process_exclusions()
        self.run_secondary_analysis()
        self.clear_affected_graph_cache()
        self.save_analysis()
        log_elapsed_time('Analysis Time', start_time)

    def check_required_files(self) -> bool:
        """
        Check for required analysis files and prompt user if they're missing.
            
        Returns:
            bool: True if analysis should proceed, False if it should be cancelled
        """
        missing_files = {}
        
        # Check for API trace file
        trace_path = self.settings["paths"]["trace"]
        if not os.path.exists(trace_path):
            missing_files['trace'] = trace_path
                
        # Check for CAPA file
        capa_path = self.settings["paths"]["capa"]
        if not os.path.exists(capa_path):
            missing_files['capa'] = capa_path
                
        # Check for user xrefs file - only add if others are missing
        xrefs_path = self.settings["paths"]["xrefs"]
        if not os.path.exists(xrefs_path) and missing_files:
            missing_files['xrefs'] = xrefs_path
            
        # If only user xrefs is missing or notifications are suppressed, proceed
        if not missing_files or (len(missing_files) == 1 and 'xrefs' in missing_files) or self.settings["suppress_notifications"]:
            return True
            
        # Show dialog
        dialog = MissingFilesDialog(missing_files)
        result = dialog.exec_()
        
        return result == QDialog.Accepted

    def clear_affected_graph_cache(self) -> None:
        """
        Clear graph cache entries for references affected by the new analysis.
        """
        affected_entities = set()

        # Identify affected entities using leaf functions
        for leaf_func_ea in self.leaf_funcs:
            if leaf_func_ea in self.paths[self.current_analysis_ep]:
                if leaf_func_ea in self.global_xrefs:
                    affected_entities.update(self.global_xrefs[leaf_func_ea][self.COMBINED_XREFS])

        # Clear cache entries for affected entities
        for e_index in affected_entities:
            if e_index in self.graph_cache:
                del self.graph_cache[e_index]

        log(f'Cleared {len(affected_entities)} affected graph cache entries')

    def insert_path(self, existing_paths: List[List[int]], new_path: List[int]) -> List[List[int]]:
        """
        Insert a new path into the existing paths if not already present.

        Args:
            existing_paths (List[List[int]]): The list of existing paths.
            new_path (List[int]): The new path to insert.

        Returns:
            List[List[int]]: The updated list of paths.
        """
        if new_path not in existing_paths:
            existing_paths.append(new_path)
        return existing_paths

    def generate_simple_call_paths(self, initial: int, final: int, max_limit: int = 10000) -> List[List[int]]:
        """
        Generate call paths between two functions.

        Args:
            initial (int): The starting function address.
            final (int): The ending function address.
            max_limit (int): The maximum number of paths to generate. Defaults to 10000.

        Returns:
            List[List[int]]: A list of call paths between the initial and final functions.
        """
        all_paths = []
        path_buffer = deque([[final]])

        log(f'Building call paths :: {idc.get_func_name(initial)} -> {idc.get_func_name(final)}')
        xref_cache = {}
        while path_buffer and len(all_paths) < max_limit and len(path_buffer) < max_limit:
            current_path = path_buffer.popleft()
            refs = set()
            target = current_path[-1]
            if target not in xref_cache:
                refs = set()
                for cross_ref in idautils.XrefsTo(target):
                    ref_func = idaapi.get_func(cross_ref.frm)
                    if ref_func:
                        ref_start = ref_func.start_ea
                        refs.add(ref_start)
                xref_cache[target] = refs
            else:
                refs = xref_cache[target]

            if refs:
                for ref in refs:
                    if ref in current_path:
                        continue
                    if ref == initial:
                        all_paths = self.insert_path(all_paths, (current_path + [ref])[::-1])
                    else:
                        path_buffer.append(current_path + [ref])

            elif len(current_path) > 0 and initial not in current_path:
                continue  # Skip this path as it doesn't lead to initial

            elif len(current_path) > 0 and initial in current_path:
                all_paths = self.insert_path(all_paths, current_path[::-1])
        return all_paths

    def generate_all_simple_call_paths_for_ep(self) -> None:
        """
        Generate all call paths for the current entry point.
        """
        if self.current_analysis_ep not in self.paths:
            self.paths[self.current_analysis_ep] = {}

        for func_ea in self.leaf_funcs:
            if self.current_analysis_ep != func_ea:
                # Check if the paths from current_analysis_ep to func_ea are already stored
                if func_ea not in self.paths[self.current_analysis_ep]:
                    _paths = self.generate_simple_call_paths(self.current_analysis_ep, func_ea)
                    if len(_paths):
                        self.paths[self.current_analysis_ep][func_ea] = _paths

    def is_node_in_existing_paths(self, node_ea: int) -> bool:
        """
        Check if a node is in any existing paths.

        Args:
            node_ea (int): The address of the node to check.

        Returns:
            bool: True if the node is in existing paths, False otherwise.
        """
        for ep in self.paths:
            for func_ea, paths in self.paths[ep].items():
                for path in paths:
                    if node_ea in path:
                        ep_name = idc.get_func_name(self.current_analysis_ep)
                        log(f'Function @ 0x{self.current_analysis_ep:x} ({ep_name}) has already been analyzed in a prior analysis as a node.')
                        return True
        return False
    
    def is_simple_api_thunk(self, func_ea: int) -> bool:
        """
        Check if a function is a simple API thunk - a thunk function that only 
        imports one direct API.

        A simple API thunk is defined as:
        1. Has FUNC_THUNK flag set
        2. Has exactly one direct API import
        3. No other types of references (strings, libs, etc)

        Args:
            func_ea (int): Address of function to check

        Returns:
            bool: True if function is a simple API thunk, False otherwise
        """
        # First check if it's marked as a thunk
        if not idc.get_func_flags(func_ea) & idc.FUNC_THUNK:
            return False

        # Check if we have xref data for this function
        if func_ea not in self.global_xrefs:
            return False

        # Get direct xrefs
        direct_xrefs = self.global_xrefs[func_ea][self.DIRECT_XREFS]
        
        # Should have exactly one import and no other references
        if len(direct_xrefs['imports']) != 1:
            return False
            
        # Check other reference types are empty
        if (direct_xrefs['libs'] or direct_xrefs['strings'] or 
            direct_xrefs['capa'] or direct_xrefs['api_trace']):
            return False

        return True
    
    def rename_cluster_functions(self) -> None:
        """
        Rename functions based on their roles in clusters, following a strict priority:
        
        Priority (to determine final category):
        1. Multi-Cluster (xutil_): Functions that belong to multiple clusters.
        2. Cluster-Specific (cluster prefix): Functions that belong to exactly one cluster.
        3. Intermediate (xint_): True intermediate nodes that:
        - Appear in intermediate paths
        - Are not in any cluster nodes
        - Are not in artifact_functions
        - Are not cluster references
        4. Unclustered (xunc_): Functions not part of any cluster and not intermediate.
        """
        KNOWN_PREFIXES = {'xunc_', 'xint_', 'xutil_'}

        if not self.clusters or not self.cluster_analysis:
            log("No cluster data available for function renaming")
            return
        
        try:

            # Helper to parse cluster IDs from various formats
            def parse_cluster_id(cluster_id_str: str) -> Optional[int]:
                # Handle various formats: "cluster_XXXX", "cluster.id.XXXX", or pure integer strings.
                if cluster_id_str.startswith("cluster_"):
                    try:
                        return int(cluster_id_str.split("_")[1])
                    except (ValueError, IndexError):
                        return None
                elif cluster_id_str.startswith("cluster.id."):
                    parts = cluster_id_str.split(".")
                    if len(parts) >= 3:
                        try:
                            return int(parts[-1])
                        except ValueError:
                            return None
                    return None
                else:
                    try:
                        return int(cluster_id_str)
                    except ValueError:
                        return None

            # Step 1: Gather all necessary data
            func_clusters = defaultdict(set)  # func_ea -> set of cluster IDs

            def map_function_clusters(cluster):
                for node in cluster.nodes:
                    func_clusters[node].add(cluster.id)
                for subcluster in cluster.subclusters:
                    map_function_clusters(subcluster)

            for cluster in self.clusters:
                map_function_clusters(cluster)

            all_functions = set(idautils.Functions())

            # Recursively gather all cluster nodes, root nodes, and cluster_refs from all levels
            def gather_all_cluster_nodes(clusters):
                all_nodes = set()
                def recurse(c):
                    all_nodes.update(c.nodes)
                    all_nodes.add(c.root_node)
                    all_nodes.update(c.cluster_refs.keys())
                    for sc in c.subclusters:
                        recurse(sc)
                for top_cluster in clusters:
                    recurse(top_cluster)
                return all_nodes

            # Combine all cluster nodes (including nested subclusters) for quick membership checks
            all_cluster_nodes = gather_all_cluster_nodes(self.clusters)

            # Identify true intermediate functions
            # A node is intermediate if it appears in intermediate_paths but is not:
            # - In cluster nodes or cluster refs
            # - In artifact_functions
            potential_intermediates = set()
            for cluster in self.clusters:
                for _, paths in cluster.intermediate_paths.items():
                    for path in paths:
                        for node in path:
                            if (node not in cluster.nodes and 
                                node not in cluster.cluster_refs and
                                node not in self.artifact_functions):
                                potential_intermediates.add(node)

            intermediate_funcs = {f for f in potential_intermediates 
                                if f not in all_cluster_nodes and f not in self.artifact_functions}

            # Step 2: Classify each function
            func_classification = {}

            # Identify multi-cluster functions
            multi_cluster_funcs = {func_ea for func_ea, clusters in func_clusters.items() if len(clusters) > 1}

            # Identify single-cluster functions
            single_cluster_funcs = {func_ea for func_ea, clusters in func_clusters.items() if len(clusters) == 1}

            # Functions not in any cluster
            no_cluster_funcs = all_functions - single_cluster_funcs - multi_cluster_funcs

            # Classify according to priority
            # - multi_cluster_funcs: 'xutil_'
            # - single_cluster_funcs: 'cluster_specific'
            # - no_cluster_funcs + intermediate: 'xint_'
            # - no_cluster_funcs + not intermediate: 'xunc_'
            for f_ea in multi_cluster_funcs:
                func_classification[f_ea] = 'xutil_'
            for f_ea in single_cluster_funcs:
                func_classification[f_ea] = 'cluster_specific'
            for f_ea in no_cluster_funcs:
                if f_ea in intermediate_funcs:
                    func_classification[f_ea] = 'xint_'
                else:
                    func_classification[f_ea] = 'xunc_'

            # Step 3: Determine cluster-specific prefixes
            cluster_prefix_map = {}
            for cluster_id_str, analysis in self.cluster_analysis.get('clusters', {}).items():
                prefix = analysis.get('function_prefix')
                if prefix:
                    cid = parse_cluster_id(cluster_id_str)
                    if cid is None:
                        log(f"Invalid cluster id format: {cluster_id_str}")
                    else:
                        cluster_prefix_map[cid] = prefix

            # Build reverse mapping: function -> cluster_id (for single cluster funcs)
            func_single_cluster_id = {}
            for f_ea in single_cluster_funcs:
                # Exactly one cluster_id in func_clusters[f_ea]
                cid = next(iter(func_clusters[f_ea]))
                func_single_cluster_id[f_ea] = cid

            # Step 4: Rename functions
            def has_known_prefix(func_ea):
                old_name = idc.get_func_name(func_ea)
                if not old_name:
                    return True  # Not a valid function name, skip
                return any(old_name.startswith(p) for p in KNOWN_PREFIXES)

            def rename_function(func_ea, new_prefix, allow_cluster_prefix_check=False):
                # Check if this is a simple API thunk
                if self.is_simple_api_thunk(func_ea):
                    return
                
                old_name = idc.get_func_name(func_ea)
                if not old_name:
                    # Not a valid function name or no name known, skip
                    return
                
                # If this function already has a known prefix, skip
                if has_known_prefix(func_ea):
                    return
                
                # If applying a cluster-specific prefix, also check if old_name already starts with that prefix
                if allow_cluster_prefix_check and new_prefix and old_name.startswith(new_prefix + '_'):
                    # Already has this cluster prefix
                    return
                
                # If cluster prefix provided, ensure it ends with '_'
                if new_prefix and not new_prefix.endswith('_'):
                    new_prefix += '_'
                
                new_name = f"{new_prefix}{old_name}"
                if idaapi.set_name(func_ea, new_name, idaapi.SN_FORCE):
                    log(f"Renamed {old_name} -> {new_name}")
                else:
                    log(f"Failed to rename {old_name} -> {new_name}")

            # Handle multi-cluster (xutil_)
            for f_ea, category in func_classification.items():
                if category == 'xutil_':
                    rename_function(f_ea, 'xutil', allow_cluster_prefix_check=False)

            # Handle cluster-specific functions
            for f_ea, category in func_classification.items():
                if category == 'cluster_specific':
                    cid = func_single_cluster_id[f_ea]
                    prefix = cluster_prefix_map.get(cid, None)
                    if prefix:
                        # For cluster-specific prefixes, check again if prefix already applied
                        rename_function(f_ea, prefix, allow_cluster_prefix_check=True)

            # Handle intermediate (xint_)
            for f_ea, category in func_classification.items():
                if category == 'xint_':
                    rename_function(f_ea, 'xint', allow_cluster_prefix_check=False)

            # Handle unclustered (xunc_)
            for f_ea, category in func_classification.items():
                if category == 'xunc_':
                    rename_function(f_ea, 'xunc', allow_cluster_prefix_check=False)

            log("Function renaming complete")
            
        except Exception as e:
            log(f"Error during function renaming: {str(e)}")
