"""Pinned privileged peer binaries and a non-hijackable subprocess environment."""

from __future__ import annotations

import os
import re

TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
RUNUSER = "/usr/sbin/runuser"
PSQL = "/usr/bin/psql"
CREATEDB = "/usr/bin/createdb"
SS = "/usr/bin/ss"
PG_LSCLUSTERS = "/usr/bin/pg_lsclusters"
_SAFE_LOCALE = re.compile(r"^[A-Za-z_][A-Za-z0-9._@+-]*$")


def peer_subprocess_env(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return a minimal env that cannot hijack privileged peer commands.

    Inherited ``PG*``, ``PATH``, and dynamic-loader variables are dropped.
    Commands run with a fixed trusted PATH and absolute binaries so executable
    substitution cannot redirect apply or inventory inspection.
    """

    inherited = os.environ if source is None else source
    env = {"PATH": TRUSTED_PATH}
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "TZ"):
        value = inherited.get(key)
        if value and _SAFE_LOCALE.fullmatch(value):
            env[key] = value
    return env
