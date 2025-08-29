# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

__all__ = ('run', 'split_kwargs')

from typing import Any
from collections.abc import Sequence
import subprocess
import logging

log = logging.getLogger(__name__)


def run(*args: Any, start_terminal_window: bool = False,
        **kwargs: Any) -> subprocess.CompletedProcess[str | bytes]:
    """
    Run the command described by args.

    Wait for command to complete, then return a subprocess.CompletedProcess instance.
    :param args: command line arguments which are provided to E-Sys.bat
    :param start_terminal_window: start command in separate console window (for server mode)
    :param kwargs: arguments tu control subprocess execution
    :return: subprocess.CompletedProcess instance
    """
    if start_terminal_window:  # pragma: no cover
        args = ("cmd.exe", "/C", "start", *args)
    output: subprocess.CompletedProcess[str | bytes] = subprocess.run(
        [str(arg) for arg in args], check=kwargs.pop("check", True), **kwargs)
    print_cmd = [("*****" if isinstance(arg, run.SafeString) else arg) for arg in args]
    log.debug(f"cmd:{print_cmd}, returncode:{output.returncode}")
    return output


run.CompletedProcess = subprocess.CompletedProcess

run.PIPE    = subprocess.PIPE
run.STDOUT  = subprocess.STDOUT
run.DEVNULL = subprocess.DEVNULL

run.SubprocessError    = subprocess.SubprocessError
run.TimeoutExpired     = subprocess.TimeoutExpired
run.CalledProcessError = subprocess.CalledProcessError

run.SafeString = type("SafeString", (str,), dict())


def split_kwargs(kwargs: dict[str, Any], forbidden_kwargs: Sequence[str]) \
        -> tuple[dict[str, Any], dict[str, Any]]:
    allowed_kwargs  = {key: val for key, val in kwargs.items()
                       if key not in forbidden_kwargs}
    reserved_kwargs = {key: val for key, val in kwargs.items()
                       if key in forbidden_kwargs}
    return (allowed_kwargs, reserved_kwargs)
