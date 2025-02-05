# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

__all__ = ('issubtype', 'issequence', 'isiterable', 'remove_all')

from typing import Any, Sequence, Iterable, List
from collections import abc
try:
    import clr
    from System import String
    del clr
except ImportError:
    String = str


def issubtype(x: Any, t: Any) -> bool:
    return isinstance(x, type) and issubclass(x, t)


def issequence(x: Any) -> bool:
    return (isinstance(x, (Sequence, abc.Sequence))
            and not isinstance(x, (bytes, str, String)))


def isiterable(x: Any) -> bool:
    return (isinstance(x, (Iterable, abc.Iterable))
            and not isinstance(x, (bytes, str, String)))


def remove_all(list: List, value: Any) -> None:  # noqa: A002
    list[:] = (item for item in list if item != value)
