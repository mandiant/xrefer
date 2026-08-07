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

"""Ghidra hands back URI-style paths; Windows cannot open them.

``Program.getExecutablePath()`` returns "/D:/dir/sample.bin" on Windows —
a leading slash in front of the drive letter. Python's ``open()`` rejects
that with ``OSError: [Errno 22] Invalid argument``, and because every
derived path (the ``.xrefer`` cache, ``_capa.json``, ``_user_xrefs.txt``,
``_trace.zip``) is built from that string, a headless Windows run does the
entire analysis and then fails at save time.

Found by CI: ``ghidra backend windows-latest`` failed while the identical
Linux job passed, because on Linux a leading slash is simply correct.

These tests import the normaliser directly — the module pulls in nothing
from Ghidra at import time, so they run on any machine.
"""

import ntpath
import posixpath

import pytest

from xrefer.backend.ghidra.backend import _native_path


@pytest.mark.parametrize(
    "uri_path",
    [
        "/D:/a/xrefer/xrefer/sample.bin",  # the exact path from the CI failure
        "/C:/Users/runneradmin/sample.bin",
        "/C:\\Users\\runneradmin\\sample.bin",
        "/z:/lower/case/drive.bin",
    ],
)
def test_drive_letter_paths_lose_the_leading_slash(uri_path):
    """A Windows drive path must not keep the URI's leading slash."""
    result = _native_path(uri_path)

    assert not result.startswith("/"), f"leading slash survived: {result!r}"
    # Second character is the colon precisely when the drive letter leads.
    assert result[1] == ":", f"drive letter not at the front: {result!r}"


@pytest.mark.parametrize(
    "native_path",
    [
        "/home/vboxuser/sample.bin",
        "/tmp/sample.bin",
        "/Users/analyst/sample.bin",  # macOS
        "relative/sample.bin",
        "sample.bin",
    ],
)
def test_posix_paths_are_left_alone(native_path):
    """The fix must be inert everywhere except Windows drive paths.

    Guards the obvious wrong fix — stripping every leading slash, which
    would turn every absolute POSIX path into a relative one.
    """
    assert _native_path(native_path) == native_path


def test_normalised_path_is_openable_by_the_host_rules():
    """The result must satisfy the platform's own notion of 'absolute'.

    ``ntpath``/``posixpath`` are used explicitly rather than ``os.path`` so
    the Windows behaviour is asserted from a Linux runner too — otherwise
    this regression can only be caught on Windows, which is how it shipped.
    """
    windows_result = _native_path("/D:/a/xrefer/sample.bin")
    assert ntpath.isabs(windows_result), f"not absolute on Windows: {windows_result!r}"
    # ntpath.isabs() alone cannot catch this bug — it calls the unfixed
    # "/D:/..." absolute too. The drive check is what actually pins it.
    assert ntpath.splitdrive(windows_result)[0].lower() == "d:", f"no drive: {windows_result!r}"

    posix_result = _native_path("/home/analyst/sample.bin")
    assert posixpath.isabs(posix_result), f"not absolute on POSIX: {posix_result!r}"


def test_derived_sibling_paths_stay_on_the_same_drive():
    """The cache/capa/user-xrefs siblings are built by string suffixing.

    If the base path is wrong they are all wrong together, which is what
    the CI log showed: capa, user_xrefs and the .xrefer cache every one
    reported under '/D:/...'.
    """
    base = _native_path("/D:/a/xrefer/xrefer/sample.bin")

    for suffix in (".xrefer", "_capa.json", "_user_xrefs.txt", "_trace.zip"):
        derived = base + suffix
        assert ntpath.isabs(derived), f"derived path not absolute: {derived!r}"
        assert ntpath.splitdrive(derived)[0].lower() == "d:", f"lost the drive: {derived!r}"
