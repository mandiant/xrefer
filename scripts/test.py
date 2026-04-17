#!/usr/bin/env python3
"""
Backward-compatible launcher for the packaged XRefer CLI.
"""

import os
import sys
from pathlib import Path


def main() -> None:
    project_dir = os.environ.get("PROJECT")
    if project_dir is None:
        project_dir = Path(__file__).resolve().parent.parent / "plugins"
    else:
        project_dir = Path(project_dir)

    if not project_dir.exists():
        raise OSError(f"PROJECT_DIR does not exist: {project_dir}")

    sys.path.insert(0, str(project_dir))

    from xrefer.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
