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

import subprocess
import sys

_original_popen = subprocess.Popen

# asciinet when imported on windows while running openjdk, ends up displaying a console window
# since asciinet is not maintained anymore submitting a PR is futile and in order to avoid forking
# our own copy we will replace the Popen function temporarily to appropriately execute javaw.exe
# and avoid spawning any unnecessary console windows


def hooking_popen(*args, **kwargs):
    """
    A replacement for subprocess.Popen that intercepts calls from asciinet
    and modifies them so the Java console window won't appear.
    """
    args = list(args)
    if args:
        cmd = args[0]
        if isinstance(cmd, list):
            # If the command is something like ["java", "-classpath", ...] on Windows,
            # we switch "java" -> "javaw" or do creationflags below
            if sys.platform.startswith("win") and cmd and cmd[0].lower() == "java":
                cmd[0] = "javaw"  # Switch to a windowless Java

    # Also, to avoid popping up a console on Windows, set CREATE_NO_WINDOW
    if sys.platform.startswith("win"):
        # Combine or set the creationflags
        creationflags = kwargs.pop("creationflags", 0)
        creationflags |= subprocess.CREATE_NO_WINDOW
        kwargs["creationflags"] = creationflags

    return _original_popen(*args, **kwargs)


# -- 1) Patch Popen BEFORE importing asciinet
subprocess.Popen = hooking_popen

# -- 2) Now import asciinet (which will import "from subprocess import Popen"),
#       so it picks up our patched Popen.
import asciinet

# -- 3) Restore original Popen so everything behaves normally
subprocess.Popen = _original_popen


from . import core, lang, legacy, llm, loaders, plugin
