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


"""Public interface for language analyzers."""

from functools import lru_cache
from xrefer.core.helpers import log
from .lang_base import LanguageBase

__all__ = ("LanguageBase", "get_language_object", "language_classes")


@lru_cache(maxsize=1)
def language_classes() -> tuple[type[LanguageBase], ...]:
    """Lazy list of registered language analyzers."""

    from .lang_rust import LangRust

    return (LangRust,)


def get_language_object() -> LanguageBase:
    """Return the language implementation that matches the active backend."""

    from .lang_default import LangDefault

    lang_classes = language_classes()
    log(f"Found language modules: {', '.join(cls.__name__ for cls in lang_classes)}")

    for lang_class in lang_classes:
        lang_obj = lang_class()
        if lang_obj.lang_match():
            log(f"{lang_class.__name__} matches current binary, initializing...")
            lang_obj.initialize()
            return lang_obj

    default_lang = LangDefault()
    default_lang.initialize()
    return default_lang
