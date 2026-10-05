"""Hermes v2 — autonomous operations agent for Unraid.

Beacon observes. Netdata adds depth. Hermes understands and acts.
"""

import os

VERSION = "2.0.0"
GIT_SHA = os.environ.get("HERMES_GIT_SHA", "dev")
BUILD_TIME = os.environ.get("HERMES_BUILD_TIME", "unknown")

__version__ = VERSION


def version_info() -> dict:
    return {"version": VERSION, "git_sha": GIT_SHA, "build_time": BUILD_TIME}
