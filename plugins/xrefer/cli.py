#!/usr/bin/env python3
"""
Unified XRefer CLI backed by the packaged xrefer module.
"""

import argparse
import sys
import traceback
import json
from importlib.util import find_spec
from pathlib import Path
from typing import Any, Literal

BACKEND = Literal["ida", "binaryninja", "ghidra"]


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
        xrefer_file = Path(f"{file_path}.xrefer")
        if xrefer_file.exists():
            print(f"[+] Removing previous XRefer output: {xrefer_file}")
            xrefer_file.unlink()


def _print_completion_summary(xrefer_obj: "XRefer") -> None:
    """Print a consistent completion summary that surfaces warnings/errors."""
    status_prefix = "[+]"
    status_msg = "XRefer analysis complete"
    if getattr(xrefer_obj, "analysis_errors", None):
        status_prefix = "[x]"
        status_msg = "XRefer analysis finished with errors"
    elif getattr(xrefer_obj, "analysis_warnings", None):
        status_prefix = "[!]"
        status_msg = "XRefer analysis complete with warnings"

    print(f"{status_prefix} {status_msg}, results saved to {xrefer_obj.settings['paths']['analysis']}")

    for err in getattr(xrefer_obj, "analysis_errors", []):
        print(f"[x] {err}")
    for warn in getattr(xrefer_obj, "analysis_warnings", []):
        print(f"[!] {warn}")


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

    return {"ida_undo": ida_undo, "idapro": idapro}


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


def analysis_ida(filepath: Path, modules: dict[str, Any] | None = None, *, xrefer_kwargs: dict[str, Any] | None = None):
    """Run XRefer analysis with IDA Pro backend."""
    import idapro

    idapro.get_library_version()

    from xrefer.core.analyzer import XRefer

    params: dict[str, Any] = {"auto_analyze": True}
    if xrefer_kwargs:
        params.update(xrefer_kwargs)

    xrefer_obj = XRefer(**params)  # This automatically calls load_analysis() when auto_analyze=True
    _print_completion_summary(xrefer_obj)
    return xrefer_obj


def analysis_binaryninja(bv, modules: dict[str, Any] | None = None, *, xrefer_kwargs: dict[str, Any] | None = None):
    """Run XRefer analysis with Binary Ninja backend."""
    backend_module = modules["backend_module"]
    BackendManager = modules["BackendManager"]

    backend_manager = BackendManager()
    backend = backend_manager.create_backend("binaryninja", bv=bv)
    backend_manager.set_active_backend(backend)
    backend_module.Backend = backend
    from xrefer.core.analyzer import XRefer

    params: dict[str, Any] = {"auto_analyze": True}
    if xrefer_kwargs:
        params.update(xrefer_kwargs)

    xrefer_obj = XRefer(**params)  # This automatically calls load_analysis() when auto_analyze=True
    _print_completion_summary(xrefer_obj)
    return xrefer_obj


def analysis_ghidra(_filepath: Path, modules: dict[str, Any] | None = None, *, xrefer_kwargs: dict[str, Any] | None = None):
    """Run XRefer analysis with Ghidra backend."""
    backend_module = modules["backend_module"]
    BackendManager = modules["BackendManager"]

    backend_manager = BackendManager()
    backend = backend_manager.create_backend("ghidra")
    backend_manager.set_active_backend(backend)

    backend_module.Backend = backend
    from xrefer.core.analyzer import XRefer

    params: dict[str, Any] = {"auto_analyze": True}
    if xrefer_kwargs:
        params.update(xrefer_kwargs)

    xrefer_obj = XRefer(**params)  # This automatically calls load_analysis() when auto_analyze=True
    _print_completion_summary(xrefer_obj)
    return xrefer_obj


def _analyze_ida(
    file_path: Path,
    auto_analysis: bool = True,
    save_changes: bool = False,
    force_analysis: bool = False,
    *,
    xrefer_kwargs: dict[str, Any] | None = None,
) -> None:
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
        return analysis_ida(file_path, modules=modules, xrefer_kwargs=xrefer_kwargs)
    finally:
        idapro.close_database(save=save_changes)


def _analyze_binaryninja(
    file_path: Path,
    auto_analysis: bool = True,
    save_changes: bool = False,
    force_analysis: bool = False,
    *,
    xrefer_kwargs: dict[str, Any] | None = None,
) -> None:
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

        xrefer_obj = analysis_binaryninja(bv, modules=modules, xrefer_kwargs=xrefer_kwargs)

        if save_changes:
            bv.save_auto_snapshot()
            print(f"[+] Saved Binary Ninja database: {bndb_path}")

        return xrefer_obj
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


def _analyze_ghidra(
    file_path: Path,
    auto_analysis: bool = True,
    save_changes: bool = False,
    force_analysis: bool = False,
    *,
    xrefer_kwargs: dict[str, Any] | None = None,
) -> None:
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
        xrefer_obj = analysis_ghidra(file_path, modules=modules, xrefer_kwargs=xrefer_kwargs)
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
        return xrefer_obj


def parse_entry_point(value: str) -> int:
    """Parse entry point argument accepting decimal or hex strings."""
    try:
        ep = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid entry point address: {value}") from exc
    if ep < 0:
        raise argparse.ArgumentTypeError("Entry point must be non-negative")
    return ep


def maybe_prompt_for_llm_settings(settings_path: Path, cli_api_key: str | None = None, llm_disabled: bool = False) -> None:
    # Nothing to prompt for if the user disabled the LLM or already supplied a
    # key on the command line.
    if llm_disabled or cli_api_key:
        return
    settings = _load_llm_settings(settings_path)
    if not settings.get("llm_lookups", True):
        return

    missing = _missing_llm_fields(settings)
    if not missing:
        return

    print(f"[!] LLM lookups are enabled but missing: {', '.join(missing)}.")
    if not sys.stdin.isatty():
        print("[!] Running without LLM for this invocation. Re-run in a TTY to enter your API key.")
        return

    print("Do you want to configure LLM access now? (y/N): ", end="")
    choice = input().strip().lower()
    if choice not in {"y", "yes"}:
        print("[!] Continuing without LLM for this run. Configure later by editing the settings file.")
        return

    model_prompt = f"Enter model id [{settings['llm_model_id']}]: "
    model_id = input(model_prompt).strip() or settings["llm_model_id"]

    api_key = input("Enter API key (leave empty to cancel): ").strip()
    if not api_key:
        print("[!] No API key provided. Continuing without LLM for this run.")
        return

    settings["api_key"] = api_key
    settings["llm_model_id"] = model_id

    try:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(settings_path, "w") as f:
            json.dump(settings, f, indent=4)
        print(f"[+] Saved LLM settings to {settings_path}")
    except Exception as exc:
        print(f"[!] Warning: Failed to save settings to {settings_path}: {exc}")
        print("[!] Continuing without LLM for this run.")


def _load_llm_settings(settings_path: Path) -> dict[str, Any]:
    settings = {"llm_lookups": True, "llm_model_id": "gemini/gemini-flash-latest", "api_key": ""}
    if settings_path.exists():
        try:
            settings.update(json.loads(settings_path.read_text()))
        except Exception as exc:
            print(f"[!] Warning: Failed to read settings file {settings_path}, using defaults for this run: {exc}")
    return settings


def _env_has_provider_key(model_id: str) -> bool:
    """True if litellm can resolve the provider's API key from the environment
    (the provider-standard vars: GEMINI_API_KEY, OPENAI_API_KEY, etc.)."""
    if not model_id:
        return False
    try:
        import litellm
        return bool(litellm.validate_environment(model=model_id).get("keys_in_environment"))
    except Exception:
        return False


def _missing_llm_fields(settings: dict[str, Any]) -> list[str]:
    missing = []
    model_id = settings.get("llm_model_id", "") or ""
    if not model_id:
        missing.append("llm_model_id")
    # Local (Ollama) models authenticate via the base URL, not a key; a hosted
    # model is satisfied by either a saved key or a provider env var.
    is_local = model_id.startswith("ollama")
    if not is_local and not settings.get("api_key") and not _env_has_provider_key(model_id):
        missing.append("api_key")
    return missing


def build_settings_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Translate CLI flags into a settings-override dict that is deep-merged on
    top of settings.json for the run. Only keys the user actually passed appear,
    so unset flags never clobber saved settings.
    """
    overrides: dict[str, Any] = {}
    if getattr(args, "model", None):
        overrides["llm_model_id"] = args.model
    if getattr(args, "api_key", None):
        overrides["api_key"] = args.api_key
    if getattr(args, "api_base", None):
        overrides["api_base"] = args.api_base
    if getattr(args, "llm", None) is not None:
        overrides["llm_lookups"] = args.llm
    if getattr(args, "git_lookups", None) is not None:
        overrides["git_lookups"] = args.git_lookups

    # Heavy/light model resolution. --model is the HEAVY model (deep cluster
    # analysis); the LIGHT model runs the high-volume categorization.
    #   --model X                  -> X for both (collapse; one model, one key)
    #   --model X --light-model Y  -> heavy X, light Y
    #   --light-model Y            -> heavy from settings/default, light Y
    if getattr(args, "light_model", None):
        overrides["use_light_model"] = True
        overrides["light_model_id"] = args.light_model
        if getattr(args, "light_api_key", None):
            overrides["light_api_key"] = args.light_api_key
            overrides["light_use_primary_key"] = False
        else:
            # Reuse the primary key (correct for the same provider or a local
            # Ollama light model, which needs no key at all).
            overrides["light_use_primary_key"] = True
    elif getattr(args, "model", None):
        # A single --model with no --light-model means "use this one model for
        # everything": collapse the split so categorization uses --model (and
        # its key) instead of the default flash-lite light model.
        overrides["use_light_model"] = False

    paths: dict[str, str] = {}
    if getattr(args, "capa", None):
        paths["capa"] = str(Path(args.capa).resolve())
    if getattr(args, "trace", None):
        paths["trace"] = str(Path(args.trace).resolve())
    if getattr(args, "user_xrefs", None):
        paths["xrefs"] = str(Path(args.user_xrefs).resolve())
    if paths:
        overrides["paths"] = paths
    return overrides


def cli():
    """Command line interface."""
    available_backends = detect_available_backends()

    parser = argparse.ArgumentParser(description="Unified XRefer CLI for multiple backends", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("file", type=Path, help="Path to the file to analyze")
    parser.add_argument("--backend", choices=available_backends, required=True, help=f"Analysis backend to use (available: {', '.join(available_backends)})")
    parser.add_argument("--save", action="store_true", help="Save changes to database/project")
    parser.add_argument("--auto-analysis", action="store_true", help="Run auto analysis (default: True)", default=True)
    parser.add_argument(
        "--mode",
        choices=["light", "full"],
        default="light",
        help=(
            "Analyzer mode (default: light). 'light' produces the SAME report as "
            "'full', just faster: it skips interactive-only work (indirect-xref "
            "propagation, per-function context tables) that the report does not "
            "use, so its saved .xrefer cache is report-only. Use '--mode full' "
            "when you also want a complete, GUI-reusable .xrefer cache."
        ),
    )
    parser.add_argument("--report-data-mode", choices=["html", "json", "none"], default="html", help="Report output format: html (standalone), json (data only), or none")
    parser.add_argument("--force", action="store_true", help="Remove previous artifacts and re-analyze")
    parser.add_argument("--entry-point", type=parse_entry_point, help="Override entry point address (decimal or hex like 0x401000)")
    parser.add_argument("-L", "--logfile", help="Output log file path")

    settings_group = parser.add_argument_group(
        "settings overrides",
        "Override ~/.xrefer/settings.json for this run only. Precedence: these flags > "
        "environment > settings.json > defaults. Add --save-settings to persist them.",
    )
    settings_group.add_argument(
        "--model",
        help="LLM model id used for BOTH the deep cluster analysis and categorization (unless "
        "--light-model is given). E.g. gemini/gemini-flash-latest, openai/gpt-5, "
        "anthropic/claude-opus-4-5, ollama_chat/llama3.1.",
    )
    settings_group.add_argument(
        "--api-key",
        help="LLM provider API key. If omitted, the provider's standard environment variable is used "
        "(GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, XAI_API_KEY, DASHSCOPE_API_KEY).",
    )
    settings_group.add_argument(
        "--api-base",
        help="Base URL for a local / self-hosted (Ollama) model, e.g. http://localhost:11434.",
    )
    settings_group.add_argument(
        "--light-model",
        help="Optional separate (cheaper / local) model for the high-volume categorization task, e.g. "
        "ollama_chat/llama3.1 or gemini/gemini-flash-lite-latest. Without this, --model is used for "
        "categorization too.",
    )
    settings_group.add_argument(
        "--light-api-key",
        help="API key for --light-model (defaults to reusing --api-key; a local Ollama --light-model "
        "needs none).",
    )
    settings_group.add_argument(
        "--llm",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable LLM lookups (cluster analysis + categorization). --no-llm runs the "
        "structural analysis only. Default: from settings.",
    )
    settings_group.add_argument(
        "--git-lookups",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable enriching strings via public GitHub code search (slower; off by default).",
    )
    settings_group.add_argument("--capa", help="Path to a capa JSON results file (default: <binary>_capa.json).")
    settings_group.add_argument("--trace", help="Path to an API trace file (default: <binary>_trace.zip).")
    settings_group.add_argument("--user-xrefs", help="Path to a user cross-references file (default: <binary>_user_xrefs.txt).")
    settings_group.add_argument(
        "-o", "--output",
        help="Report output path (default: <binary>_report.html, or _report_data.json for --report-data-mode json).",
    )
    settings_group.add_argument(
        "--save-settings",
        action="store_true",
        help="Persist the supplied overrides (model / key / api-base / --llm / --git-lookups, and input "
        "paths scoped to this binary) to ~/.xrefer/settings.json for future runs.",
    )

    args = parser.parse_args()

    if not available_backends:
        print("[x] Error: No analysis backends available. Please install IDA Pro, Binary Ninja, or Ghidra.")
        sys.exit(1)

    file_path = args.file.resolve()
    if not file_path.exists():
        print(f"[x] Error: File not found: {file_path}")
        sys.exit(1)

    settings_path = Path.home() / ".xrefer" / "settings.json"
    maybe_prompt_for_llm_settings(settings_path, cli_api_key=args.api_key, llm_disabled=(args.llm is False))

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_file_handle = None

    if args.logfile:
        log_file = Path(args.logfile).resolve()
        print(f"[+] Redirecting logs to: {log_file}")
        log_file_handle = open(log_file, "w")
        sys.stdout = log_file_handle
        sys.stderr = log_file_handle

    xrefer_kwargs = {
        "auto_analyze": args.auto_analysis,
        "mode": args.mode,
        "report_data_mode": args.report_data_mode,
    }
    if args.entry_point is not None:
        xrefer_kwargs["ep"] = args.entry_point

    overrides = build_settings_overrides(args)
    if overrides:
        xrefer_kwargs["settings_overrides"] = overrides
        if args.save_settings:
            xrefer_kwargs["persist_settings"] = True
    elif args.save_settings:
        print("[!] --save-settings was given but no override flags were set; nothing to persist.")
    if args.output:
        xrefer_kwargs["report_path"] = str(Path(args.output).resolve())

    try:
        print(f"[+] Starting XRefer analysis with {args.backend} backend")
        print(f"[+] File: {file_path}")
        print(f"[+] Auto-analysis: {args.auto_analysis}")
        print(f"[+] Analyzer mode: {args.mode}")
        print(f"[+] Report data mode: {args.report_data_mode}")
        print(f"[+] Save changes: {args.save}")
        print(f"[+] Force re-analysis: {args.force}")
        if args.model:
            print(f"[+] Model: {args.model}")
        if args.light_model:
            print(f"[+] Categorization (light) model: {args.light_model}")
            if (not args.light_api_key and not args.light_model.startswith("ollama")
                    and args.model
                    and args.model.split("/", 1)[0] != args.light_model.split("/", 1)[0]):
                print("[!] --light-model is a different provider than --model and no --light-api-key was "
                      "given; it will reuse the primary key and likely fail categorization. Pass --light-api-key.")
        elif args.model:
            print("[+] Categorization uses the same model as analysis (--model)")
        if args.llm is not None:
            print(f"[+] LLM lookups: {'enabled' if args.llm else 'disabled'}")
        if args.git_lookups is not None:
            print(f"[+] GitHub string lookups: {'enabled' if args.git_lookups else 'disabled'}")
        if args.output:
            print(f"[+] Report output: {Path(args.output).resolve()}")
        if args.save_settings and overrides:
            print("[+] Persisting these settings to ~/.xrefer/settings.json")
        if args.entry_point is not None:
            print(f"[+] Entry point override: {args.entry_point:#x}")

        analysis_result = None
        try:
            if args.backend == "ida":
                analysis_result = _analyze_ida(file_path, args.auto_analysis, args.save, args.force, xrefer_kwargs=xrefer_kwargs)
            elif args.backend == "binaryninja":
                analysis_result = _analyze_binaryninja(file_path, args.auto_analysis, args.save, args.force, xrefer_kwargs=xrefer_kwargs)
            elif args.backend == "ghidra":
                print(
                    """
[🐉] Here be dragons (literally).
>   The Ghidra backend may contain more bugs than other backends like IDA Pro or Binary Ninja.
>   If you encounter issues, please report them at https://github.com/mandiant/xrefer/issues
""",
                    file=sys.stderr,
                )
                analysis_result = _analyze_ghidra(file_path, args.auto_analysis, args.save, args.force, xrefer_kwargs=xrefer_kwargs)
            else:
                print(f"[x] Error: Unknown backend: {args.backend}")
                sys.exit(1)
            if analysis_result and getattr(analysis_result, "analysis_errors", None):
                print("[x] Analysis completed with errors (see above)")
                sys.exit(1)
            elif analysis_result and getattr(analysis_result, "analysis_warnings", None):
                print("[!] Analysis completed with warnings (see above)")
            else:
                print("[+] Analysis completed successfully")
        except KeyboardInterrupt:
            print("\n[!] Analysis interrupted by user")
            sys.exit(1)
        except Exception as e:
            if isinstance(e, EnvironmentError):
                sys.exit(1)
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
