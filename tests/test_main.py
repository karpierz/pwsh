# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

import unittest
from functools import partial
from pathlib import Path
import os, shutil, tempfile
import threading

from rich.pretty import pprint
pprint = partial(pprint, max_length=500)

import pwsh
from pwsh import PowerShell

here = Path(__file__).resolve().parent
data_dir = here/"data"


class PowerShellTestCase:#(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ps = PowerShell()
        cls.lock = threading.Lock()

    def setUp(self):
        self.lock.acquire()

    def tearDown(self):
        self.lock.release()