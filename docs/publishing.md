# Publishing XRefer as a pip package

Everything below assumes the repo root and a clean checkout of the
commit you intend to release.

### Step 0 — one-time account setup

1. Create accounts on <https://pypi.org> **and** <https://test.pypi.org>
   (separate account databases — registering on one does not register
   the other).
2. Enable 2FA on both. PyPI has required it for all uploads since 2024;
   without it the upload is rejected.
3. Decide how you will authenticate:
   - **Trusted Publishing (recommended)** — GitHub Actions authenticates
     to PyPI over OIDC. No token is ever created, stored, or leaked. See
     [Step 5](#step-5--automate-it-trusted-publishing).
   - **API token** — for manual uploads from a laptop. Create it at
     *Account settings → API tokens*, scoped to the project once the
     project exists. Store it in `~/.pypirc` (mode `600`) or pass it as
     `TWINE_PASSWORD` with `TWINE_USERNAME=__token__`.

### Step 1 — bump the version

The version lives in exactly one place:

```
plugins/xrefer/_version.py  ->  __version__ = "1.1.20260804"
```

Format is `MAJOR.MINOR.YYYYMMDD`. `pyproject.toml` reads it statically
(`dynamic = ["version"]`), and so do `xrefer.__version__`, the IDA
startup log, the About dialog and the HTML report — never edit the
version anywhere else. Commit the bump.

### Step 2 — build the distributions

```bash
python -m pip install --upgrade build twine
rm -rf dist/ build/            # stale artifacts get uploaded otherwise
python -m build                # produces dist/*.whl and dist/*.tar.gz
```

Build **both** the wheel and the sdist. The wheel is what nearly
everyone installs; the sdist is what lets someone on an unusual platform
build from source, and what mirrors and distro packagers expect.

### Step 3 — check before uploading

```bash
twine check --strict dist/*
```

This validates that the README renders on the project page — a malformed
README is accepted by the upload API and then displays as a blank page,
which cannot be fixed without a new version.

Then verify the contents of the wheel actually match what you think you
built:

```bash
python -m zipfile -l dist/*.whl | grep -E 'data/|_version'
```

Package data has silently gone missing from this wheel more than once (a
non-recursive `package-data` glob dropped `data/agent_skills/` with no
error anywhere). `ci.yml` asserts the full expected set on every push —
if CI is green on the release commit, this is already covered.

### Step 4 — rehearse on TestPyPI, then publish

```bash
# Rehearsal — claims the name on TestPyPI only
twine upload --repository testpypi dist/*

# Install it back into a clean venv. The extra index is required:
# xrefer's dependencies (dspy, flare-capa, ...) are not on TestPyPI.
python -m venv /tmp/rehearsal
/tmp/rehearsal/bin/pip install \
    --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ \
    "xrefer[vivisect]"
/tmp/rehearsal/bin/xrefer --help
/tmp/rehearsal/bin/python -c "import xrefer; print(xrefer.__version__, xrefer.available_backends())"
```

Only when that works:

```bash
twine upload dist/*
```

The project is live at `https://pypi.org/project/xrefer/` within
seconds. Verify once more from a clean venv, this time with no extra
index:

```bash
python -m venv /tmp/live && /tmp/live/bin/pip install "xrefer[vivisect]"
/tmp/live/bin/xrefer --no-llm some_binary
```

### Step 5 — automate it (Trusted Publishing)

Manual `twine upload` is fine for the first release; after that it
should run from CI so the artifact is built on a clean machine and no
token exists to leak.

On PyPI, go to the project's *Settings → Publishing* and add a trusted
publisher: owner `mandiant`, repository `xrefer`, workflow
`publish.yml`, environment `pypi`. (Before the first release the project
does not exist yet — use *Your projects → Publishing → Add a pending
publisher* instead, which pre-authorizes the name.)

Then add `.github/workflows/publish.yml`:

```yaml
name: publish

on:
  release:
    types: [published]

jobs:
  pypi:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write      # required for OIDC; this is what replaces the token
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install --upgrade build twine
      - run: python -m build
      - run: twine check --strict dist/*
      - uses: pypa/gh-action-pypi-publish@release/v1
```

No `password:` line — the action exchanges the workflow's OIDC token for
a short-lived PyPI credential. Publishing a GitHub Release then becomes
the single release action, which also triggers `standalone.yml` to build
the one-file binaries for the same tag.

---

## Release checklist

1. `ci.yml` green on the release commit (wheel install + both backends +
   CLI/`python -m`/API on Linux and Windows).
2. Version bumped in `plugins/xrefer/_version.py` and committed.
3. `rm -rf dist/ build/ && python -m build`.
4. `twine check --strict dist/*`.
5. TestPyPI upload + clean-venv install.
6. `twine upload dist/*` (or publish a GitHub Release, with Step 5 wired
   up).
7. Clean-venv install from live PyPI, run a real analysis.
8. Tag the commit and publish the GitHub Release so `standalone.yml`
   attaches the one-file binaries.
