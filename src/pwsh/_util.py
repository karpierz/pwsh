# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

__all__ = ('issubtype', 'isiterable', 'issequence', 'remove_all')

import typing
from typing import Any
from collections.abc import Iterable, Sequence
try:
    import clr  # type: ignore[import-untyped]
    from System import String  # type: ignore[import-not-found]
    del clr
except ImportError:  # pragma: no cover
    String = str


def issubtype(x: Any, t: Any) -> bool:
    return isinstance(x, type) and issubclass(x, t)


def isiterable(x: Any) -> bool:
    return (isinstance(x, (Iterable, typing.Iterable))
            and not isinstance(x, (bytes, str, String)))


def issequence(x: Any) -> bool:
    return (isinstance(x, (Sequence, typing.Sequence))
            and not isinstance(x, (bytes, str, String)))


def remove_all(seq: list[Any], value: Any) -> None:
    seq[:] = (item for item in seq if item != value)
