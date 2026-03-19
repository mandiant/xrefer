"""Test the IDA backend adapter inside an IDA Python runtime.
Run this from IDA with a database already open and auto-analysis complete:
    File -> Script file -> scripts/ida_backend_smoke.py
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from xrefer_new.backend.ida import IDABackEnd
    backend = IDABackEnd()
    validation_issues = backend.validate()
    print("[xrefer_new] backend:", backend.name)
    print("[xrefer_new] image_base:", hex(backend.get_image_base()))
    print("[xrefer_new] sha256:", backend.get_input_sha256())
    print("[xrefer_new] entry_points:", [hex(ea) for ea in backend.get_entry_points()])
    print("[xrefer_new] validation:", validation_issues or "ok")
    print("[xrefer_new] functions:", len(list(backend.iter_functions())))
    print("[xrefer_new] imports:", len(list(backend.iter_imports())))
    print("[xrefer_new] strings:", len(list(backend.iter_strings())))
    print("[xrefer_new] callsites:", len(list(backend.iter_call_sites())))


if __name__ == "__main__":
    main()
