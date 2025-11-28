# flake8-in-file-ignores: noqa: F401

# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

from .__about__ import * ; del __about__  # type: ignore[name-defined]  # noqa

from ._pwsh import * ; del _pwsh  # type: ignore[name-defined]  # noqa
from utlx import run
from utlx import issubtype, issequence, isiterable
from utlx import unique, iter_unique

out_null = dict(stdout=run.DEVNULL, stderr=run.DEVNULL)
