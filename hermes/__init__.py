"""Hermes v2 — autonomous operations agent for Unraid.

Beacon observes. Netdata adds depth. Hermes understands and acts.
"""

import os
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

# pyproject is the single version source of truth (2.0.1 lesson: a
# hardcoded VERSION could drift across releases)
try:
    VERSION = _pkg_version("hermes-agent")
except PackageNotFoundError:  # uit source-tree zonder install
    VERSION = "2.0.1"
GIT_SHA = os.environ.get("HERMES_GIT_SHA", "dev")
BUILD_TIME = os.environ.get("HERMES_BUILD_TIME", "unknown")

__version__ = VERSION


def version_info() -> dict:
    return {"version": VERSION, "git_sha": GIT_SHA, "build_time": BUILD_TIME}
