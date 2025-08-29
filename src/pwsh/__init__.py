# flake8-in-file-ignores: noqa: F401

# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

from .__about__ import * ; del __about__  # type: ignore[name-defined]  # noqa

from ._pwsh   import * ; __all__ = _pwsh.__all__  # type: ignore[name-defined]  # noqa
from ._run    import run
from ._util   import issubtype
from ._util   import issequence
from ._util   import isiterable
from ._unique import unique
from ._unique import iter_unique
del _pwsh, _adict, _epath, _modpath  # type: ignore[name-defined]  # noqa
del _run, _util, _unique             # type: ignore[name-defined]  # noqa
out_null = dict(stdout=run.DEVNULL, stderr=run.DEVNULL)
