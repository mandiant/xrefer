import argparse
import os
import sys
import traceback
from importlib.util import find_spec
from pathlib import Path

# fmt:off
import idapro  # ensure idapro is imported before ida_undo
import ida_undo
# fmt:on
from PyQt5.QtWidgets import QApplication

_prjdir = os.environ.get("PROJECT")
if _prjdir is None:
    raise EnvironmentError("set PROJECT to the plugins dir")
PROJECT_DIR = Path(_prjdir)  # should be "pathto/xrefer/plugins"
assert PROJECT_DIR.exists(), f"PROJECT_DIR does not exist: {PROJECT_DIR}"
sys.path.insert(0, str(PROJECT_DIR.absolute()))


def ensure_qapplication():
    """Ensures a QApplication instance exists.
    Creates one if it doesn't already exist.
    """
    if QApplication.instance():
        return QApplication.instance()
    else:
        app = QApplication(sys.argv if sys.argv else ["idaclixrefer_headless"])
        return app


app = ensure_qapplication()

from xrefer.core.analyzer import XRefer

pkg_path = Path(find_spec("xrefer").origin).resolve().parent
rel_pkg_path = os.path.relpath(pkg_path, start=os.getcwd())


def analysis(filepath: Path):
    """Main analysis function"""
    xrefer_obj = XRefer()
    print(f"[+] XRefer analysis complete, results saved to {xrefer_obj.settings['paths']['analysis']}")
    return xrefer_obj


def _analyze(file_path: Path, auto_analysis: bool = True, save_changes: bool = False, force_analysis: bool = False) -> None:
    if Path(f"{str(file_path)}.id0").exists():
        if not force_analysis:
            print(f"[x] File {file_path} already analyzed. Use --force to re-analyze.")
            return
        for ext in ("id0", "id1", "id2", "nam", "til"):  # project is open!
            file_to_remove = file_path.with_name(f"{file_path.name}.{ext}")
            if file_to_remove.exists():
                print(f"[+] Removing {file_to_remove}.")
                file_to_remove.unlink()
    if force_analysis:
        for ext in ("i64", "xrefer"):  # project archived
            file_to_remove = file_path.with_name(f"{file_path.name}.{ext}")
            if file_to_remove.exists():
                print(f"[+] Removing {file_to_remove}.")
                file_to_remove.unlink()
    try:
        print(f"[+] Opening database {file_path}")
        idapro.open_database(str(file_path), run_auto_analysis=auto_analysis)
        if ida_undo.create_undo_point(b"Initial state, auto analysis"):
            print(f"[+] Successfully created an undo point.")
        else:
            print(f"[x] Failed to created an undo point.")

        _ = analysis(file_path)
        print(f"[+] XRefer analysis complete, results saved")

        if not save_changes:
            if ida_undo.perform_undo():
                print(f"[+] Successfully reverted database changes.")
            else:
                print(f"[x] Failed to revert database changes.")
    except Exception as e:
        traceback.print_exc()
        print(f"[x] Error: {e}", file=sys.stderr)
    finally:
        idapro.close_database(save=save_changes)
        return str(file_path) + ".i64.xrefer"


def cli():
    parser = argparse.ArgumentParser(description="XRefer Headless Analysis")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--save", action="store_true", help="Save changes to the database")
    parser.add_argument("--auto-analysis", action="store_true", help="Run auto analysis", default=False)
    parser.add_argument("--force", action="store_true", help="Remove previous artifacts and re-analyze", default=False)
    parser.add_argument("-o", "--output", default=None, type=Path, help="Output file path to override the default .i64.xrefer file.")
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
    print(f"[+] Analyzing file: {file_path} using XRefer.")
    print(f"{rel_pkg_path = }")
    try:
        artifact_path = _analyze(file_path, auto_analysis=args.auto_analysis, save_changes=args.save, force_analysis=args.force)
        if Path(artifact_path).exists():
            if args.output:
                if args.output.is_dir():
                    op: Path = args.output / Path(artifact_path).name
                else:
                    op: Path = args.output
                op.parent.mkdir(parents=True, exist_ok=True)
                os.rename(artifact_path, op)
                print(f"[+] Saving output to {op}.")
    except KeyboardInterrupt:
        # remove all id0, id1, id2, nam, til files
        for ext in ("id0", "id1", "id2", "nam", "til"):
            file_to_remove = file_path.with_suffix(f".{ext}")
            if file_to_remove.exists():
                print(f"[+] Removing {file_to_remove}.")
                file_to_remove.unlink()


def main():
    cli()


if __name__ == "__main__":
    main()
