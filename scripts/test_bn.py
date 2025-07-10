import argparse
import os
import sys
import traceback
from importlib.util import find_spec
from pathlib import Path

try:
    import binaryninja as bn
except ImportError as err:
    raise ImportError("Binary Ninja not found. Ensure Binary Ninja Python API is installed.") from err

_prjdir = os.environ.get("PROJECT")
if _prjdir is None:
    raise EnvironmentError("set PROJECT to the plugins dir")
PROJECT_DIR = Path(_prjdir)  # should be "pathto/xrefer/plugins"
assert PROJECT_DIR.exists(), f"PROJECT_DIR does not exist: {PROJECT_DIR}"
sys.path.insert(0, str(PROJECT_DIR.absolute()))

import xrefer.backend as backend_module
from xrefer.backend.factory import BackendManager

backend_module.Backend = None  # Force re-initialization

pkg_path = Path(find_spec("xrefer").origin).resolve().parent
rel_pkg_path = os.path.relpath(pkg_path, start=os.getcwd())


def analysis(bv: bn.BinaryView):
    """Main analysis function"""
    # Create Binary Ninja backend
    backend_manager = BackendManager()
    backend = backend_manager.create_backend("binaryninja", bv=bv)
    backend_manager.set_active_backend(backend)

    # Set the global backend variable to prevent auto-initialization
    backend_module.Backend = backend

    # Import XRefer after backend is set up
    from xrefer.core.analyzer import XRefer

    # Run XRefer analysis
    xrefer_obj = XRefer()
    print(f"[+] XRefer analysis complete, results saved to {xrefer_obj.settings['paths']['analysis']}")
    return xrefer_obj


def _analyze(file_path: Path, auto_analysis: bool = True, save_changes: bool = False, force_analysis: bool = False) -> None:
    # Check for existing Binary Ninja database
    bndb_path = file_path.with_suffix(".bndb")
    if bndb_path.exists():
        if not force_analysis:
            print(f"[x] File {file_path} already analyzed (.bndb exists). Use --force to re-analyze.")
            return
        print(f"[+] Removing existing database {bndb_path}")
        bndb_path.unlink()

    # Remove existing XRefer artifacts if force is specified
    if force_analysis:
        xrefer_path = file_path.with_suffix(".xrefer")
        if xrefer_path.exists():
            print(f"[+] Removing {xrefer_path}")
            xrefer_path.unlink()

    bv = None
    try:
        print(f"[+] Opening binary {file_path}")

        # Open the binary with Binary Ninja
        bv = bn.load(str(file_path), options={'analysis.mode': 'full' if auto_analysis else 'basic', 'analysis.suppressNewAutoFunctionAnalysis': not auto_analysis})

        if bv is None:
            raise Exception(f"Failed to load binary: {file_path}")

        print(f"[+] Binary loaded, type: {bv.view_type}")

        # Wait for analysis if requested
        if auto_analysis:
            print(f"[+] Waiting for auto-analysis to complete...")
            bv.update_analysis_and_wait()
            print(f"[+] Auto-analysis complete")

        # Create a save point (Binary Ninja doesn't have undo like IDA)
        if save_changes and not bndb_path.exists():
            print(f"[+] Creating Binary Ninja database at {bndb_path}")
            bv.create_database(str(bndb_path))

        # Run XRefer analysis
        _ = analysis(bv)
        print(f"[+] XRefer analysis complete, results saved")

        # Save changes if requested
        if save_changes and bndb_path.exists():
            print(f"[+] Saving changes to database")
            bv.save_auto_snapshot()

    except Exception as e:
        traceback.print_exc()
        print(f"[x] Error: {e}", file=sys.stderr)
    finally:
        # Close the binary view
        if bv:
            bv.file.close()

        return str(file_path) + ".xrefer"


def cli():
    parser = argparse.ArgumentParser(description="XRefer Binary Ninja Headless Analysis")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--save", action="store_true", help="Save changes to a Binary Ninja database (.bndb)")
    parser.add_argument("--auto-analysis", action="store_true", help="Run auto analysis", default=False)
    parser.add_argument("--force", action="store_true", help="Remove previous artifacts and re-analyze", default=False)
    parser.add_argument("-o", "--output", default=None, type=Path, help="Output file path to override the default .xrefer file.")
    parser.add_argument("-L", "--logfile", default=None, type=Path, help="Output log file path")
    args = parser.parse_args()

    file_path = Path(args.file)
    assert file_path.exists(), f"File {file_path} does not exist"

    if args.logfile:
        # redirect stdout and stderr to the log file
        log_file = args.logfile
        log_file.parent.mkdir(parents=True, exist_ok=True)
        sys.stdout = open(log_file, "w", encoding="utf-8")
        sys.stderr = open(log_file, "w", encoding="utf-8")
    else:
        bn.disable_default_log()

    print(f"[+] Analyzing file: {file_path} using XRefer with Binary Ninja.")
    print(f"{rel_pkg_path = }")

    try:
        artifact_path = _analyze(file_path, auto_analysis=args.auto_analysis, save_changes=args.save, force_analysis=args.force)
        if artifact_path and Path(artifact_path).exists():
            if args.output:
                if args.output.is_dir():
                    op: Path = args.output / Path(artifact_path).name
                else:
                    op: Path = args.output
                op.parent.mkdir(parents=True, exist_ok=True)
                os.rename(artifact_path, op)
                print(f"[+] Saving output to {op}.")
    except KeyboardInterrupt:
        # Clean up any temporary files
        bndb_path = file_path.with_suffix(".bndb")
        if bndb_path.exists() and not args.save:
            print(f"[+] Removing temporary database {bndb_path}")
            bndb_path.unlink()
        raise KeyboardInterrupt("Analysis interrupted by user.")


def main():
    cli()


if __name__ == "__main__":
    main()
