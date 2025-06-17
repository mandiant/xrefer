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

from xrefer.gui.helpers import log
from xrefer.lang.lang_base import LanguageBase
from xrefer.lang.lang_default import LangDefault


def get_language_modules() -> List[Type[LanguageBase]]:
    """Get all available language module classes."""
    lang_classes = []
    lang_dir = os.path.dirname(__file__)

    # Get all lang_*.py files except default and base
    lang_files = [f[:-3] for f in os.listdir(lang_dir) if f.startswith("lang_") and f.endswith(".py") and f not in ("lang_base.py", "lang_default.py", "lang_registry.py")]

    for module_name in lang_files:
        try:
            # Import module
            module = importlib.import_module(f".{module_name}", package="xrefer.lang")

            # Find language class (subclass of LanguageBase)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if name == "LangDefault":
                    continue
                if issubclass(obj, LanguageBase) and obj != LanguageBase:
                    lang_classes.append(obj)
        except Exception as e:
            log(f"Error loading language module {module_name}: {e}")

    return lang_classes


def get_language_object() -> Any:
    """Get appropriate language object for current binary."""
    # Try all non-default language modules first
    for lang_class in get_language_modules():
        try:
            lang_obj = lang_class()
            if lang_obj.lang_match():
                return lang_obj
        except Exception as e:
            log(f"Error instantiating {lang_class.__name__}: {e}")
            import traceback
            traceback.print_exc()

    # Return default as fallback
    return LangDefault()
