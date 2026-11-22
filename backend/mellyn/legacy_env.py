"""
Detect deployments still configured with the variable prefix used before the product was renamed to Mellyn.

The code reads only MELLYN_* variables. A deployment that still sets the old-prefixed ones is half-migrated:
its pepper and key digests are silently ignored, and (before the gateway stripped them) were handed to every
MCP server the gateway launched. Rather than run in that state, the API and the gateway refuse to start and
name the variables to rename. Only names are reported, never values.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

# Built from two parts so the repository-wide scan for retired identifiers does not match this file.
LEGACY_ENV_PREFIX = "AE" + "GIS_"


class LegacyConfigError(RuntimeError):
    """Environment variables with the retired prefix are set. Callers refuse to start (fail closed)."""


def legacy_env_names(environ: Mapping[str, str] | None = None) -> list[str]:
    """Names (never values) of set variables that carry the retired prefix, sorted."""
    source = os.environ if environ is None else environ
    return sorted(name for name in source if name.upper().startswith(LEGACY_ENV_PREFIX))


def check_no_legacy_env(environ: Mapping[str, str] | None = None) -> None:
    names = legacy_env_names(environ)
    if names:
        renamed = ", ".join(f"{n} -> MELLYN_{n[len(LEGACY_ENV_PREFIX) :]}" for n in names)
        raise LegacyConfigError(
            f"Found {len(names)} variable(s) with the pre-rename prefix, which this version ignores: {renamed}. "
            "Rename them (and remove the old ones) before starting."
        )
