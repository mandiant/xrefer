# Standalone XRefer (CLI, library, one-file binary)

XRefer runs outside IDA as a standalone engine. There are three ways to
use it, all sharing the same analysis pipeline:

## 1. pip install (CLI + library)

```bash
pip install xrefer            # engine + vivisect backend (bundled)
pip install xrefer[vivisect]  # + LIEF symbol/section enrichment (recommended)
pip install xrefer[ghidra]    # + pyghidra bridge (needs a Ghidra install + GHIDRA_INSTALL_DIR)
pip install xrefer[ida]       # + idalib bridge (needs IDA >= 9.0 + IDADIR/ida-config)
pip install xrefer[gui]       # + Qt abstraction for the IDA plugin GUI
```

The vivisect backend is pure-Python and arrives with the base package —
a plain `pip install xrefer` is always able to analyze binaries with no
external tools installed.

### CLI

```bash
xrefer path/to/binary                     # auto-selects a backend (vivisect always available)
python -m xrefer path/to/binary           # same thing
xrefer --backend vivisect --no-llm b.exe  # structural analysis only, no API key needed
xrefer --backend ghidra b.exe --model gemini/gemini-2.5-pro
```

Outputs land next to the binary: `<binary>_<backend>.xrefer` (analysis
cache) and `<binary>_<backend>_report.html` (standalone report; requires
LLM lookups for cluster analysis).

LLM configuration lives in `~/.xrefer/settings.json` (the CLI offers to
create it on first use) or per-run flags: `--model`, `--api-key`,
`--api-base` (Ollama), `--light-model`. `--no-llm` runs without any of
it.

### Library

```python
import xrefer

print(xrefer.available_backends())            # e.g. ['vivisect']

result = xrefer.analyze("path/to/binary", llm=False)   # auto-picks backend
result = xrefer.analyze(
    "path/to/binary",
    backend="vivisect",
    mode="light",          # or "full" for the GUI-reusable cache
    report="html",         # also write the HTML report (default: no files)
    llm=None,              # None = follow settings.json; False = force off
)

result.lang.entry_point    # resolved entry point
result.clusters            # cluster tree (walk .subclusters recursively)
```

`analyze()` returns the populated `XRefer` analyzer object — the same
object the CLI drives — so everything the report shows is reachable
programmatically.

## 2. One-file binaries (no Python required)

Standalone executables (Linux ELF / Windows EXE / macOS Mach-O) bundle
Python, the vivisect backend, and the LLM stack into a single file,
exactly like capa's release binaries:

```bash
./xrefer path/to/binary --no-llm
./xrefer path/to/binary --model gemini/gemini-2.5-pro --api-key ...
```

The standalone binary ships the vivisect backend only: IDA, Binary
Ninja, and Ghidra require a host application/JVM on the machine and
cannot be frozen into a self-contained executable.

Binaries are built per-OS by the `build standalone` GitHub Actions
workflow (`.github/workflows/standalone.yml`). To build locally:

```bash
python -m build --wheel
python -m venv /tmp/xrefer-build && . /tmp/xrefer-build/bin/activate
pip install "dist/xrefer-<version>-py3-none-any.whl[vivisect]" pyinstaller
cd .github/pyinstaller && pyinstaller xrefer.spec --noconfirm
./dist/xrefer --help
```

## 3. IDA plugin

Unchanged — see the main [README](../README.md). The standalone work
does not alter the plugin behavior; the CLI/library and the plugin share
one codebase.
