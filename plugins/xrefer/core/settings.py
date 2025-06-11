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
from time import time
from typing import Any, Dict, List

from xrefer.gui.helpers import log

from xrefer import backend

PathType = str
SamplePaths = Dict[str, Dict[PathType, str]]  # (current_idb: {path_type: path})
ExclusionData = Dict[str, List[str]]  # (category: [exclusion_items])


class XReferSettingsManager:
    """
    Manages persistent storage and retrieval of XRefer settings.

    Handles reading/writing settings files, resolving default paths,
    and managing sample-specific settings.

    Attributes:
        settings_dir (str): Directory for storing XRefer settings
        settings_file (str): Path to main settings JSON file
        exclusion_file (str): Path to exclusions JSON file
        idb_specific_paths (Set[str]): Set of path settings that can be customized per sample
        current_idb (str): Path of current IDB file
    """

    def __init__(self):
        self.settings_dir = os.path.join(os.path.expanduser("~"), ".xrefer")
        self.settings_file = os.path.join(self.settings_dir, "settings.json")
        self.exclusion_file = os.path.join(self.settings_dir, "exclusions.json")
        self.lockfile = self.settings_file + ".lock"
        os.makedirs(self.settings_dir, exist_ok=True)

        # IDB-specific settings - paths that can be customized per IDB
        self.idb_specific_paths = {"analysis", "capa", "trace", "xrefs"}
        self.current_idb = backend.sample_path()

    def get_default_settings(self) -> Dict[str, Any]:
        """Get default settings dictionary with added display options."""
        settings = {
            "llm_lookups": True,
            "git_lookups": False,
            "suppress_notifications": False,
            "llm_origin": "google",
            "llm_model": "gemini-1.5-pro",
            "api_key": "",
            "enable_exclusions": True,
            "display_options": {"auto_size_graphs": True, "hide_llm_disclaimer": False, "show_help_banner": True, "default_panel_width": 779},
            "use_default_paths": {"analysis": True, "capa": True, "trace": True, "xrefs": True, "categories": True, "exclusions": True},
            "paths": {
                "analysis": self.resolve_default_path("analysis"),
                "capa": self.resolve_default_path("capa"),
                "trace": self.resolve_default_path("trace"),
                "xrefs": self.resolve_default_path("xrefs"),
                "categories": self.resolve_default_path("categories"),
                "exclusions": self.resolve_default_path("exclusions"),
            },
            "idb_specific_paths": {},
        }
        return settings

    def resolve_default_path(self, path_type: str) -> str:
        """
        Resolve the actual default path for a given path type.

        Handles special cases like finding existing trace files with different extensions
        and constructing appropriate default paths based on IDB location.

        Args:
            path_type (str): Type of path to resolve ('analysis', 'capa', 'trace', etc.)

        Returns:
            str: Resolved default path for the specified type
        """
        idb_path = self.current_idb
        path_to_check = None
        default_trace_path = None

        for suffix in ("_trace.zip", "_trace.json", "_trace.tag"):
            path_to_check = f"{idb_path}{suffix}"
            if os.path.exists(path_to_check):
                default_trace_path = path_to_check

        if not default_trace_path:
            default_trace_path = f"{idb_path}_trace.zip"

        default_paths = {
            "analysis": f"{idb_path}.xrefer",
            "capa": f"{idb_path}_capa.json",
            "trace": default_trace_path,
            "xrefs": f"{idb_path}_user_xrefs.txt",
            "categories": os.path.join(self.settings_dir, "xrefer_categories.json"),
            "exclusions": self.exclusion_file,
        }

        return default_paths.get(path_type, "")

    def load_settings(self):
        """Load settings with locking and path resolution."""
        default_settings = self.get_default_settings()

        if not os.path.exists(self.settings_file):
            return default_settings

        try:
            with FileLockContext(self.lockfile):
                with open(self.settings_file, "r") as f:
                    settings = json.load(f)

                # Ensure all expected keys exist by updating with defaults
                self.migrate_settings(settings, default_settings)

                # Initialize idb_specific_paths if not present
                if "idb_specific_paths" not in settings:
                    settings["idb_specific_paths"] = {}

                # Resolve paths based on current settings
                for path_type in settings["paths"]:
                    if settings["use_default_paths"][path_type]:
                        settings["paths"][path_type] = self.resolve_default_path(path_type)
                    elif path_type in self.idb_specific_paths:
                        # Use sample-specific path if available and not using default
                        idb_paths: SamplePaths = settings.get("idb_specific_paths", {})
                        idb_settings = idb_paths.get(self.current_idb, {})
                        if path_type in idb_settings:
                            settings["paths"][path_type] = idb_settings[path_type]

                return settings

        except IOError:
            log("Could not acquire settings lock, using defaults")
            return default_settings
        except Exception as e:
            log(f"Error loading settings: {str(e)}")
            return default_settings

    def migrate_settings(self, current_settings: dict, default_settings: dict) -> None:
        """
        Recursively update current settings with any missing fields from defaults.

        Args:
            current_settings: Current settings dictionary to update
            default_settings: Default settings containing expected schema
        """
        for key, value in default_settings.items():
            if key not in current_settings:
                current_settings[key] = value
            elif isinstance(value, dict) and isinstance(current_settings[key], dict):
                # Recursively update nested dictionaries
                self.migrate_settings(current_settings[key], value)

    def save_settings(self, settings):
        """Save settings with locking and proper cleanup."""
        temp_file = self.settings_file + ".tmp"

        try:
            with FileLockContext(self.lockfile):
                # Create a copy to modify
                settings_to_save = settings.copy()

                # Ensure idb_specific_paths exists
                if "idb_specific_paths" not in settings_to_save:
                    settings_to_save["idb_specific_paths"] = {}

                # Handle IDB-specific paths
                for path_type in self.idb_specific_paths:
                    if not settings_to_save["use_default_paths"][path_type]:
                        # Save IDB-specific path
                        if self.current_idb not in settings_to_save["idb_specific_paths"]:
                            settings_to_save["idb_specific_paths"][self.current_idb] = {}
                        settings_to_save["idb_specific_paths"][self.current_idb][path_type] = settings_to_save["paths"][path_type]
                        # Set the main path to DEFAULT
                        settings_to_save["paths"][path_type] = ""

                # Preserve settings for other IDBs
                if os.path.exists(self.settings_file):
                    try:
                        with open(self.settings_file, "r") as f:
                            existing_settings = json.load(f)
                            if "idb_specific_paths" in existing_settings:
                                for idb, paths in existing_settings["idb_specific_paths"].items():
                                    if idb != self.current_idb:
                                        settings_to_save["idb_specific_paths"][idb] = paths
                    except Exception as e:
                        log(f"Error reading existing settings: {str(e)}")

                # Write to temp file first
                try:
                    with open(temp_file, "w") as f:
                        json.dump(settings_to_save, f, indent=4)
                        f.flush()
                        os.fsync(f.fileno())
                except Exception as e:
                    log(f"Error writing temp file: {str(e)}")
                    raise

                # Atomic rename
                try:
                    os.replace(temp_file, self.settings_file)
                except Exception as e:
                    log(f"Error during atomic rename: {str(e)}")
                    raise

        except IOError as e:
            log(f"Settings not saved: {str(e)}")
        except Exception as e:
            log(f"Unexpected error saving settings: {str(e)}")
        finally:
            # Clean up temp file
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                log(f"Error cleaning up temp file: {str(e)}")

    def get_default_exclusions(self) -> ExclusionData:
        return {"apis": [], "libs": [], "strings": [], "capa": []}

    def load_exclusions(self) -> ExclusionData:
        if not os.path.exists(self.exclusion_file):
            return self.get_default_exclusions()
        try:
            with open(self.exclusion_file, "r") as f:
                return json.load(f)
        except:
            return self.get_default_exclusions()

    def save_exclusions(self, exclusions: ExclusionData) -> None:
        with open(self.exclusion_file, "w") as f:
            json.dump(exclusions, f, indent=4)


class FileLockContext:
    """Simple cross-platform file locking using atomic file creation."""

    def __init__(self, lockfile):
        self.lockfile = lockfile

    def __enter__(self):
        attempts = 50  # 5 seconds total
        for _ in range(attempts):
            try:
                # Try to create lock file - fails if exists
                fd = os.open(self.lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.close(fd)
                return self
            except OSError:
                time.sleep(0.1)
        raise IOError("Could not acquire settings lock")

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            os.unlink(self.lockfile)
        except OSError:
            pass
