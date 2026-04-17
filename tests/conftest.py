"""Test-wide configuration helpers.

Provides compatibility for environments without pytest-cov by defining
no-op coverage options so global addopts in pyproject don't break. If
pytest-cov is available, this conftest stays inert to avoid conflicts.
"""

def pytest_addoption(parser):
    import sys
    from argparse import ArgumentError

    # If pytest-cov plugin is already loaded, do nothing to avoid conflicts
    if "pytest_cov" in sys.modules:
        return

    group = parser.getgroup("cov-compat", "coverage compat")
    try:
        group.addoption(
            "--cov",
            action="append",
            dest="cov",
            default=[],
            help="no-op compatibility option when pytest-cov is absent",
        )
    except ArgumentError:
        pass
    try:
        group.addoption(
            "--cov-report",
            action="append",
            dest="cov_report",
            default=[],
            help="no-op compatibility option when pytest-cov is absent",
        )
    except ArgumentError:
        pass
    try:
        group.addoption(
            "--no-cov-on-fail",
            action="store_true",
            dest="no_cov_on_fail",
            default=False,
            help="no-op compatibility option when pytest-cov is absent",
        )
    except ArgumentError:
        pass
