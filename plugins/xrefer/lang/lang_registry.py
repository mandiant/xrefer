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


import importlib
import inspect
import os
from typing import Any, List, Type

from xrefer.core.helpers import log
from xrefer.lang.lang_base import LanguageBase
from xrefer.lang.lang_default import LangDefault


def get_language_modules() -> List[Type[LanguageBase]]:
    """Discover all backend-neutral language module classes.

    Recursively scans the xrefer.lang package for files named 'lang_*.py'
    (excluding base/registry/default) and loads classes deriving from LanguageBase.
    """
    lang_classes: List[Type[LanguageBase]] = []
    lang_dir = os.path.dirname(__file__)

    exclude_files = {"lang_base.py", "lang_default.py", "lang_registry.py", "__init__.py"}

    for root, _dirs, files in os.walk(lang_dir):
        for filename in files:
            if not (filename.startswith("lang_") and filename.endswith(".py")):
                continue
            if filename in exclude_files:
                continue

            rel_path = os.path.relpath(os.path.join(root, filename), lang_dir)
            module_name = rel_path[:-3].replace(os.sep, ".")  # strip .py and convert to package path

            try:
                module = importlib.import_module(f".{module_name}", package="xrefer.lang")
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if name == "LangDefault":
                        continue
                    if issubclass(obj, LanguageBase) and obj is not LanguageBase:
                        lang_classes.append(obj)
            except Exception as e:
                log(f"[-] Error loading language module {module_name}: {e}")

    lang_str = ", ".join([cls.__name__ for cls in lang_classes])
    log(f"Found language modules: {lang_str}")
    return lang_classes


def get_language_object() -> Any:
    """Get appropriate language object for current binary."""
    # Try all non-default language modules first
    for lang_class in get_language_modules():
        try:
            lang_obj = lang_class()
            if lang_obj.lang_match():
                log(f"{lang_class.__name__} matches current binary, initializing...")
                # Only initialize if language matches to avoid side effects
                lang_obj.initialize()
                return lang_obj
        except Exception as e:
            log(f"[-] Error instantiating {lang_class.__name__}: {e}")
            import traceback

            traceback.print_exc()

    # Return default as fallback
    default_lang = LangDefault()
    default_lang.initialize()
    return default_lang
