# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

import unittest
from functools import partial
from pathlib import Path
import os, shutil, tempfile
import threading

from rich.pretty import pprint
pprint = partial(pprint, max_length=500)

here = Path(__file__).resolve().parent
data_dir = here/"data"


class PowerShellTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import pwsh
        cls.ps = pwsh.ps
        cls.lock = threading.Lock()

    @classmethod
    def tearDownClass(cls):
        cls.ps = None

    def setUp(self):
        self.lock.acquire()

    def tearDown(self):
        self.lock.release()

    def test_main(self):
        pass

    def test_streams(self):
        ps = self.ps
        #            Stream       Stream #  Write Cmdlet
        # ----------------------------------------------
        # output stream           1         Write-Output
        # ps.Streams.Error        2         Write-Error
        # ps.Streams.Warning      3         Write-Warning
        # ps.Streams.Verbose      4         Write-Verbose
        # ps.Streams.Debug        5         Write-Debug
        # ps.Streams.Information  6         Write-Information, Write-Host
        # ps.Streams.Progress     n/a       Write-Progress
        #
        ps.Write_Host("")
        #ps.Write_Output("Write_Output !!!")
        #ps.Write_Error("Write_Error !!!")
        ps.Write_Host("Write_Host !!!")  #, InformationAction="Ignore")
        # ps.InformationPreference = "Continue"
        ps.Write_Information("Write_Information !!!", InformationAction="Continue")
        # ps.WarningPreference = "Continue"
        ps.Write_Warning("Write_Warning !!!", WarningAction="Continue")
        # ps.VerbosePreference = "Continue"
        ps.Write_Verbose("Write_Verbose !!!", Verbose=True)
        # ps.DebugPreference = "Continue"
        ps.Write_Debug("Write_Debug !!!", Debug=True)
        # ps.ProgressPreference = "SilentlyContinue"
        # ps.ProgressPreference = "Continue"
        rmin  = 0
        rmax  = 100
        rstep = 10
        for i in range(rmin, rmax + 1, rstep):
            ps.Write_Progress("Write_Progress !!!",
                              Status=f"{i}% Complete:", PercentComplete=i)
            ps.Start_Sleep(Milliseconds=500)
        ps.Write_Host("")
