# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

from .__about__ import * ; del __about__  # noqa

from ._pwsh   import * ; __all__ = _pwsh.__all__  # noqa
from ._run    import run
from ._util   import issubtype    # noqa: F401
from ._util   import issequence   # noqa: F401
from ._util   import isiterable   # noqa: F401
from ._unique import unique       # noqa: F401
from ._unique import iter_unique  # noqa: F401
del _pwsh, _adict, _epath, _modpath, _run, _util, _unique  # noqa
out_null = dict(stdout=run.DEVNULL, stderr=run.DEVNULL)
