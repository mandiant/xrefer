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

import idaapi
from typing import Optional

from xrefer.core.view import XReferView
from xrefer.core.action_handlers import *
from xrefer.core.helpers import *


initialized: bool = False
plugin_instance = None


class XReferPlugin(idaapi.plugin_t):
    """
    Main plugin class for XRefer.
    
    Attributes:
        flags (int): Plugin flags indicating it should stay resident in memory.
        wanted_name (str): Display name of the plugin in IDA.
        wanted_hotkey (str): Default hotkey to activate the plugin.
        xrefer_view (Optional[XReferView]): The plugin's main view instance.
        version (float): Plugin version number.
    """
    flags: int = idaapi.PLUGIN_KEEP
    wanted_name: str = "XRefer"
    wanted_hotkey: str = "Alt-8"

    def __init__(self):
        """Initialize plugin with empty view."""
        self.xrefer_view = None
        self.version = 1.0

    def init(self) -> int:
        """
        Initialize the plugin by registering menu actions.
        
        This method is called by IDA when the plugin is loaded. It registers various
        menu actions under the Edit/XRefer menu and displays a loading message.
        
        Returns:
            int: PLUGIN_KEEP to indicate plugin should stay resident in memory.
        """
        global plugin_instance
        global initialized
        self.xrefer_view: Optional[XReferView] = None
        plugin_instance = self
        if not initialized:
            initialized = True
            register_menu_action('Edit/XRefer/Run Analysis/', 'XRefer:start_analysis_default',
                                 'Default Entrypoint', StartHandler())
            register_menu_action('Edit/XRefer/Run Analysis/', 'XRefer:start_analysis_custom',
                                 'Custom Entrypoint', StartHandlerCustomEntrypoint())
            register_menu_action('Edit/XRefer/Run Analysis/', 'XRefer:cluster_everything',
                                 '(Re-)run Cluster Analysis on all Functions (default)', ClusterEverythingHandler())
            register_menu_action('Edit/XRefer/Run Analysis/', 'XRefer:rerun_cluster_analysis',
                                 '(Re-)run Cluster Analysis on Interesting Functions', ClusterInterestingFunctionsHandler())
            register_menu_action('Edit/XRefer/Run Analysis/', 'XRefer:rerun_artifact_analysis',
                                 '(Re-)run Artifact Analysis', ArtifactAnalysisHandler())
            register_menu_action('Edit/XRefer/', 'XRefer:show_window',
                                 'Show Window', ShowWindowHandler())
            register_menu_action('Edit/XRefer/', 'XRefer:dump_indirect_calls',
                                 'Dump Indirect Calls', DumpIndirectCallsHandler())
            register_menu_action('Edit/XRefer/', 'XRefer:sync_imagebase',
                                 'Re-sync Imagebase', SyncImageBaseHandler())
            register_menu_action('Edit/XRefer/Rename Functions/', 'XRefer:rename_rust',
                                 'Rename based on Rust compiler strings', RustRenameHandler())
            register_menu_action('Edit/XRefer/Rename Functions/', 'XRefer:rename_cluster',
                                'Apply cluster analysis prefixes', ClusterRenameHandler())
            register_menu_action('Edit/XRefer/Generate Report', 'XRefer:generate_report',
                                 'Generate Anatomy Report (HTML)', GenerateReportHandler())
            register_menu_action('Edit/XRefer/Configure', 'XRefer:Rust:configure',
                                 'Configure', XReferSettingsHandler())
            register_menu_action('Edit/XRefer/About', 'XRefer:Rust:about',
                                 'About', AboutDialogHandler())
        idaapi.msg(f'[XRefer] Loaded\n')
        return idaapi.PLUGIN_KEEP

    def start(self, ep: Optional[int] = None) -> None:
        """
        Start the XRefer view with an optional entry point.
        
        Args:
            ep (Optional[int]): Memory address to use as entry point for analysis.
                            If None, default entry point will be used.
        """
        if self.xrefer_view is None:
            idaapi.msg("[XRefer] Initializing XRefer View\n")
            self.xrefer_view = XReferView(self, ep)

    def run(self, arg: int) -> None:
        """
        Run the plugin when activated via hotkey.
        
        This method is called when the plugin's hotkey is pressed. It displays
        a message indicating the plugin version and how to access its menu.
        
        Args:
            arg (int): IDA argument value (unused).
        """
        log(f'Binary Navigator v{self.version} is loaded. Browse to Edit -> XRefer.')


class ContextHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if plugin_instance:
            tft = idaapi.get_widget_type(form)
            if tft in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
                menu_path: str = 'XRefer/'
                menu_id: str = 'XRefer:analyse_custom_entrypoint'
                label: str = 'Analyse this function as a custom entrypoint'
                register_popup_action(form, popup, menu_path, menu_id, label, AddEntrypointHandler(), label)


hooks = ContextHooks()
hooks.hook()