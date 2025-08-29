# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

from typing import Protocol, Any
import subprocess

class RunType(Protocol):

    def __call__(self, *args: Any, start_terminal_window: bool = False,
                 **kwargs: Any) -> subprocess.CompletedProcess[str | bytes]: ...

    CompletedProcess: type

    PIPE:    int
    STDOUT:  int
    DEVNULL: int

    SubprocessError:    type
    TimeoutExpired:     type
    CalledProcessError: type

    SafeString: type

run: RunType
