"""Hermes plugin: register the jev-kit tool-call gate as a pre_tool_call hook.

Mode and question set come from the environment:

  JEV_KIT_HOOK_MODE                shadow (default) or enforce
  JEV_KIT_HOOK_QUESTION_SET_PATH   absolute path to tool-call-gate.json

Resolving the kit: the plugin imports `jev_kit` from a source checkout, not
site-packages (the Hermes runtime python manages its own site-packages and has
previously dropped third-party editable installs, so a site-packages dependency
is not durable here). Resolution order:

  1. $JEV_KIT_SRC  (absolute path to the checkout's src/ directory)
  2. ~/jev-agent-kit/src  (the conventional single-checkout location)

Import is deferred to register() so a missing checkout is a loud, local,
diagnosable registration error instead of a plugin-load crash.
"""

import os
import sys
from pathlib import Path

_ENV_SRC = "JEV_KIT_SRC"
_FALLBACK = Path.home() / "jev-agent-kit" / "src"


def _kit_src() -> Path:
    raw = os.environ.get(_ENV_SRC, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return _FALLBACK


def register(ctx):
    src = _kit_src()
    if not (src / "jev_kit").is_dir():
        raise RuntimeError(
            f"jev-gate: the jev-agent-kit source tree was not found at {src}. "
            f"Set {_ENV_SRC} to the checkout's src/ directory."
        )
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from jev_kit.hooks.hermes import register as _register_gate

    _register_gate(ctx)