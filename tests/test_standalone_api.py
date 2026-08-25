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

"""Tests for the standalone surface: xrefer.analyze() / available_backends()
argument validation and the truthful IDA-backend detection (the idapro
PyPI shim arrives transitively on every install, so mere importability
must NOT count as IDA being available)."""

import json
import platform

import pytest

from xrefer.api import analyze, available_backends
from xrefer.cli import _ida_install_configured, detect_available_backends


# ── xrefer.analyze() argument validation ─────────────────────────────────


def test_analyze_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / "does_not_exist.exe")


def test_analyze_unknown_backend_raises(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x00\x00")
    with pytest.raises(ValueError, match="Unknown backend"):
        analyze(target, backend="radare2")


def test_analyze_unavailable_backend_raises(tmp_path, monkeypatch):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x00\x00")
    import xrefer.cli as cli_mod

    monkeypatch.setattr(cli_mod, "detect_available_backends", lambda: ["vivisect"])
    with pytest.raises(ValueError, match="not available"):
        analyze(target, backend="binaryninja")


def test_available_backends_returns_detected():
    # vivisect arrives transitively via flare-capa -> always present in
    # any working install (incl. the test env).
    backends = available_backends()
    assert isinstance(backends, list)
    assert "vivisect" in backends


# ── truthful IDA detection ───────────────────────────────────────────────


def _isolate_ida_config(monkeypatch, tmp_path):
    """Point every lookup the detector does at a controlled empty home.

    Returns the directory the detector actually reads ida-config.json from
    on THIS platform — ``~/.idapro`` on POSIX, but
    ``%APPDATA%/Hex-Rays/IDA Pro`` on Windows (see cli._ida_install_
    configured). Hardcoding the POSIX path made the "configured" test fail
    on Windows, and made the "empty config" test pass there for the wrong
    reason: no config found at all, rather than one found and rejected.
    """
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.delenv("IDAUSR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    # Path.home() honors HOME on POSIX; on Windows it uses USERPROFILE.
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    if platform.system() == "Windows":
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
        return tmp_path / "AppData" / "Hex-Rays" / "IDA Pro"
    return tmp_path / ".idapro"


def test_ida_not_configured_without_install(monkeypatch, tmp_path):
    _isolate_ida_config(monkeypatch, tmp_path)
    assert _ida_install_configured() is False


def test_ida_configured_via_idadir(monkeypatch, tmp_path):
    _isolate_ida_config(monkeypatch, tmp_path)
    monkeypatch.setenv("IDADIR", str(tmp_path))
    assert _ida_install_configured() is True


def test_ida_configured_via_config_json(monkeypatch, tmp_path):
    cfg_dir = _isolate_ida_config(monkeypatch, tmp_path)
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "ida-config.json").write_text(json.dumps({"Paths": {"ida-install-dir": "/opt/ida"}}))
    assert _ida_install_configured() is True


def test_ida_empty_config_not_configured(monkeypatch, tmp_path):
    cfg_dir = _isolate_ida_config(monkeypatch, tmp_path)
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "ida-config.json").write_text(json.dumps({"Paths": {"ida-install-dir": ""}}))
    assert _ida_install_configured() is False


def test_detect_excludes_ida_when_shim_only(monkeypatch, tmp_path):
    """The idapro PyPI shim is importable in this test env (transitive via
    flare-capa) yet must not surface 'ida' without a configured install."""
    _isolate_ida_config(monkeypatch, tmp_path)
    assert "ida" not in detect_available_backends()
