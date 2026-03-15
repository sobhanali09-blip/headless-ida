"""shared — Shared utilities for ida_server / ida_cli.

Re-exports from common.py and arch_detect.py so callers can
``from shared import load_config, arch_detect`` etc.
"""

import os as _os

from .common import (               # noqa: F401
    load_config,
    init_registry_paths,
    acquire_lock,
    release_lock,
    load_registry,
    save_registry,
    file_md5,
    remove_auth_token,
)
from .arch_detect import arch_detect  # noqa: F401

# Absolute path to the bundled config.json
CONFIG_JSON = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "config.json")
