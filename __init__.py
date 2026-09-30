# SPDX-License-Identifier: GPL-3.0-only
"""Zenella package entry point. Install the directory, not this file at plugins/ root."""
# Binary Ninja may attempt to import a misplaced root __init__.py as a standalone
# plugin. Do not perform a relative import without a parent package.
if __package__:
    try:
        import binaryninja as _binaryninja
    except ModuleNotFoundError as exc:
        if exc.name != "binaryninja":
            raise
    else:
        from . import amd_zen_ucode
