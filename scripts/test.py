#!/usr/bin/env python3
"""
Unified XRefer testing script
"""

import argparse
import os
import sys
import traceback
from importlib.util import find_spec
from pathlib import Path
from typing import Any, Literal

BACKEND = Literal["ida", "binaryninja", "ghidra"]

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

_prjdir = os.environ.get("PROJECT") or os.path.join(os.path.dirname(__file__), "..", "plugins")
if _prjdir is None:
    raise OSError("set PROJECT to the plugins dir")
PROJECT_DIR = Path(_prjdir)
assert PROJECT_DIR.exists(), f"PROJECT_DIR does not exist: {PROJECT_DIR}"
sys.path.insert(0, str(PROJECT_DIR.absolute()))

pkg_path = Path(find_spec("xrefer").origin).resolve().parent


class BackendNotAvailableError(Exception):
    """Raised when a requested backend is not available."""


def detect_available_backends() -> list[str]:
    """Detect which backends are available on the system."""
    backends = []
    for spec, name in [("idapro", "ida"), ("binaryninja", "binaryninja"), ("pyghidra", "ghidra")]:
        if find_spec(spec) is not None:
            backends.append(name)
    return backends


def get_backend_extensions(backend: BACKEND) -> list[str]:
    """Get file extensions associated with each backend."""
    # Note: Ghidra uses project directories, not simple file extensions
    extensions = {
        "ida": [".id0", ".id1", ".id2", ".nam", ".til", ".i64"],
        "binaryninja": [".bndb"],
        # Ghidra handled specially in cleanup_previous_analysis
    }
    return extensions.get(backend, [])


def cleanup_previous_analysis(file_path: Path, backend: str, force: bool = False) -> None:
    """Clean up previous analysis artifacts for the specified backend."""
    if not force:
        return

    if backend == "ghidra":
        # Common pyghidra project layouts to remove:
        #  - <binary>_ghidra (directory)
        # Also clear any stale .xrefer next to the binary path
        import shutil

        candidates = [
            file_path.parent / f"{file_path.name}_ghidra",
            file_path.parent / f"{file_path.stem}.rep",
            file_path.with_suffix(".xrefer"),
        ]

        for path in candidates:
            try:
                if path.exists():
                    if path.is_dir():
                        print(f"[+] Removing previous Ghidra project: {path}")
                        shutil.rmtree(path)
                    else:
                        print(f"[+] Removing previous artifact: {path}")
                        path.unlink()
            except Exception as e:
                print(f"[!] Warning: Failed to remove {path}: {e}")
    else:
        # Generic cleanup via known extensions
        extensions = get_backend_extensions(backend)
        for ext in extensions:
            artifact_file = file_path.with_suffix(ext)
            if artifact_file.exists():
                print(f"[+] Removing previous artifact: {artifact_file}")
                artifact_file.unlink()
        # Remove .xrefer output files
        xrefer_file = file_path.with_suffix(".xrefer")
        if xrefer_file.exists():
            print(f"[+] Removing previous XRefer output: {xrefer_file}")
            xrefer_file.unlink()


def setup_ida_backend():
    """Set up IDA Pro backend requirements."""
    try:
        try:
            import idapro
        except ImportError:
            raise ImportError("Please ensure IDA Pro is installed and the idapro module is available.")
        import ida_undo
    except ImportError as e:
        raise BackendNotAvailableError(f"IDA Pro backend not available: {e}")

    return { "ida_undo": ida_undo, "idapro": idapro}


def setup_binaryninja_backend():
    """Set up Binary Ninja backend requirements."""
    try:
        import binaryninja as bn
    except ImportError as e:
        raise BackendNotAvailableError(f"Binary Ninja backend not available: {e}")

    import xrefer.backend as backend_module
    from xrefer.backend.factory import BackendManager

    backend_module.Backend = None  # Force re-initialization

    return {"bn": bn, "backend_module": backend_module, "BackendManager": BackendManager}


def setup_ghidra_backend():
    """Set up Ghidra backend requirements."""
    try:
        import pyghidra
    except ImportError as e:
        raise BackendNotAvailableError(f"Ghidra backend not available: {e}")

    import xrefer.backend as backend_module
    from xrefer.backend.factory import BackendManager

    backend_module.Backend = None  # Force re-initialization

    return {"pyghidra": pyghidra, "backend_module": backend_module, "BackendManager": BackendManager}


def analysis_ida(filepath: Path, modules: dict[str, Any] | None = None):
    """Run XRefer analysis with IDA Pro backend."""
    import idapro

    idapro.get_library_version()

    from xrefer.core.analyzer import XRefer

    try:
        xrefer_obj = XRefer(auto_analyze=True)  # This automatically calls load_analysis()
        print(f"[+] XRefer analysis complete, results saved to {xrefer_obj.settings['paths']['analysis']}")
        return xrefer_obj
    except Exception as e:
        print(f"[x] Analysis failed: {e}")
        traceback.print_exc()
        raise


def analysis_binaryninja(bv, modules: dict[str, Any] | None = None):
    """Run XRefer analysis with Binary Ninja backend."""
    backend_module = modules["backend_module"]
    BackendManager = modules["BackendManager"]

    backend_manager = BackendManager()
    backend = backend_manager.create_backend("binaryninja", bv=bv)
    backend_manager.set_active_backend(backend)
    backend_module.Backend = backend
    from xrefer.core.analyzer import XRefer

    xrefer_obj = XRefer(auto_analyze=True)  # This automatically calls load_analysis()
    print(f"[+] XRefer analysis complete, results saved to {xrefer_obj.settings['paths']['analysis']}")
    return xrefer_obj


def analysis_ghidra(_filepath: Path, modules: dict[str, Any] | None = None):
    """Run XRefer analysis with Ghidra backend."""
    backend_module = modules["backend_module"]
    BackendManager = modules["BackendManager"]

    backend_manager = BackendManager()
    backend = backend_manager.create_backend("ghidra")
    backend_manager.set_active_backend(backend)

    backend_module.Backend = backend
    from xrefer.core.analyzer import XRefer

    xrefer_obj = XRefer(auto_analyze=True)  # This automatically calls load_analysis()
    print(f"[+] XRefer analysis complete, results saved to {xrefer_obj.settings['paths']['analysis']}")
    return xrefer_obj


def _analyze_ida(file_path: Path, auto_analysis: bool = True, save_changes: bool = False, force_analysis: bool = False) -> None:
    """Analyze with IDA Pro backend."""
    modules = setup_ida_backend()
    idapro = modules["idapro"]

    cleanup_previous_analysis(file_path, "ida", force_analysis)

    project_exists = any(file_path.with_suffix(ext).exists() for ext in [".id0", ".i64"])
    if project_exists and not force_analysis:
        print(f"[+] Opening existing IDA project for {file_path}")
    else:
        print(f"[+] Creating new IDA project for {file_path}")

    try:
        idapro.open_database(str(file_path), run_auto_analysis=auto_analysis)
        analysis_ida(file_path, modules=modules)
    finally:
        idapro.close_database(save=save_changes)


def _analyze_binaryninja(file_path: Path, auto_analysis: bool = True, save_changes: bool = False, force_analysis: bool = False) -> None:
    """Analyze with Binary Ninja backend."""
    import binaryninja

    modules = setup_binaryninja_backend()
    bn: "binaryninja" = modules["bn"]

    cleanup_previous_analysis(file_path, "binaryninja", force_analysis)
    # Determine BN database path alongside the input file
    bndb_path = file_path.with_suffix(".bndb")
    print(f"[+] Loading binary file: {file_path}")
    bn.disable_default_log()
    bv = bn.load(str(file_path), options={"analysis.mode": "full" if auto_analysis else "basic"})

    if bv is None:
        raise Exception(f"Failed to load binary: {file_path}")

    try:
        if auto_analysis and not bndb_path.exists():
            print("[+] Waiting for auto-analysis...")
            bv.update_analysis_and_wait()

        if save_changes and not bndb_path.exists():
            print(f"[+] Creating Binary Ninja database: {bndb_path}")
            bv.create_database(str(bndb_path))

        # Save snapshot before analysis
        if save_changes:
            bv.save_auto_snapshot()

        analysis_binaryninja(bv, modules=modules)

        if save_changes:
            bv.save_auto_snapshot()
            print(f"[+] Saved Binary Ninja database: {bndb_path}")

    finally:
        bv.file.close()


def configure_fast_ghidra_analysis(program, auto_analysis: bool) -> None:
    """Wrapper to configure fast Ghidra analysis."""
    if not auto_analysis:
        return

    # Use the backend's optimized configuration
    from xrefer.backend.ghidra.backend import configure_fast_analysis
    print("[*] Configuring optimized Ghidra analysis (disabling decompiler analyzers)...")
    configure_fast_analysis(program)


def _analyze_ghidra(file_path: Path, auto_analysis: bool = True, save_changes: bool = False, force_analysis: bool = False) -> None:
    """Analyze with Ghidra backend."""
    modules = setup_ghidra_backend()
    pyghidra = modules["pyghidra"]

    cleanup_previous_analysis(file_path, "ghidra", force_analysis)

    pyghidra.start()

    # Open with analyze=False to allow custom analyzer configuration
    with pyghidra.open_program(str(file_path), analyze=False) as flat_api:
        from ghidra.program.util import GhidraProgramUtilities

        program = flat_api.getCurrentProgram()
        configure_fast_ghidra_analysis(program, auto_analysis)

        if auto_analysis and GhidraProgramUtilities.shouldAskToAnalyze(program):
            flat_api.analyzeAll(program)

        from xrefer.backend.factory import backend_manager

        ghidra_backend = backend_manager.create_backend("ghidra", program=flat_api.getCurrentProgram())
        backend_manager.set_active_backend(ghidra_backend)
        analysis_ghidra(file_path, modules=modules)
        if save_changes:
            print("[+] Saving Ghidra project...")
            try:
                program = flat_api.getCurrentProgram()
                # End any active transaction before saving
                if program.hasActiveTrxs():
                    program.endTrx()
                flat_api.saveProgram(program)
            except Exception as save_error:
                print(f"[!] Save failed: {save_error}")
                # Continue without failing the analysis


def cli():
    """Command line interface."""
    available_backends = detect_available_backends()

    parser = argparse.ArgumentParser(description="Unified XRefer testing script for multiple backends", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)

    parser.add_argument("file", type=Path, help="Path to the file to analyze")
    parser.add_argument("--backend", choices=available_backends, required=True, help=f"Analysis backend to use (available: {', '.join(available_backends)})")
    parser.add_argument("--save", action="store_true", help="Save changes to database/project")
    parser.add_argument("--auto-analysis", action="store_true", help="Run auto analysis (default: False)")
    parser.add_argument("--force", action="store_true", help="Remove previous artifacts and re-analyze")
    parser.add_argument("-L", "--logfile", help="Output log file path")

    args = parser.parse_args()

    if not available_backends:
        print("[x] Error: No analysis backends available. Please install IDA Pro, Binary Ninja, or Ghidra.")
        sys.exit(1)

    file_path = args.file.resolve()
    if not file_path.exists():
        print(f"[x] Error: File not found: {file_path}")
        sys.exit(1)

    # Store original streams for cleanup
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_file_handle = None

    # Redirect logs if specified
    if args.logfile:
        log_file = Path(args.logfile).resolve()
        print(f"[+] Redirecting logs to: {log_file}")
        log_file_handle = open(log_file, "w")
        sys.stdout = log_file_handle
        sys.stderr = log_file_handle

    try:
        print(f"[+] Starting XRefer analysis with {args.backend} backend")
        print(f"[+] File: {file_path}")
        print(f"[+] Auto-analysis: {args.auto_analysis}")
        print(f"[+] Save changes: {args.save}")
        print(f"[+] Force re-analysis: {args.force}")

        try:
            if args.backend == "ida":
                _analyze_ida(file_path, args.auto_analysis, args.save, args.force)
            elif args.backend == "binaryninja":
                _analyze_binaryninja(file_path, args.auto_analysis, args.save, args.force)
            elif args.backend == "ghidra":
                print("""
[🐉] Here be dragons (literally).
>   The Ghidra backend may contain more bugs than other backends like IDA Pro or Binary Ninja.
>   If you encounter issues, please report them at https://github.com/mandiant/xrefer/issues
""", file=sys.stderr)
                _analyze_ghidra(file_path, args.auto_analysis, args.save, args.force)
            else:
                print(f"[x] Error: Unknown backend: {args.backend}")
                sys.exit(1)
            print("[+] Analysis completed successfully")
        except KeyboardInterrupt:
            print("\n[!] Analysis interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n[x] Analysis failed: {e}")
            traceback.print_exc()
            sys.exit(1)
    finally:
        # Restore original streams and close log file
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        if log_file_handle:
            log_file_handle.close()


def main():
    cli()


if __name__ == "__main__":
    main()
