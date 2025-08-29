# Copyright (c) 2018 Adam Karpierz
# SPDX-License-Identifier: Zlib

__all__ = ('module_path',)

import sys
import types
import inspect
from pathlib import Path


def module_path(module: types.ModuleType | None = None,
                *, level: int = 1) -> Path:
    if module is not None:
        mfile = inspect.getfile(module)
    else:
        frame = sys._getframe(level)
        module = inspect.getmodule(frame)
        if module is not None:
            mfile = inspect.getfile(module)
        else:
            mfile = frame.f_globals["__file__"]
    return Path(mfile).resolve().parent
