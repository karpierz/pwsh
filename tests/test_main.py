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
        from System.Management import Automation
        cls.Automation = Automation

    @classmethod
    def tearDownClass(cls):
        cls.ps = None

    def setUp(self):
        self.lock.acquire()

    def tearDown(self):
        self.lock.release()


class PowerShell_Main_TestCase(PowerShellTestCase):

    def test_main(self):
        ps = self.ps

        sys_drive = ps.env.SystemDrive
        sys_root  = ps.env.SystemRoot
        temp_dir  = ps.env.TEMP
        non_exist = ps.env.__NON_EXISTENT_ENV_VARIABLE_

        value = ps.Host

        value = ps.Error

        value = ps.ErrorView

        #@ErrorView.setter
        #def ErrorView(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("ErrorView", value)

        value = ps.ErrorActionPreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.Stop)

        #@ErrorActionPreference.setter
        #def ErrorActionPreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("ErrorActionPreference", value)
        #    self.ErrorActionPreference

        #@contextlib.contextmanager
        #def ErrorAction(self, preference):
        #    eap = self.ErrorActionPreference
        #    self.ErrorActionPreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.ErrorActionPreference = eap

        value = ps.WarningPreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.Continue)

        #@WarningPreference.setter
        #def WarningPreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("WarningPreference", value)
        #    self.WarningPreference

        #@contextlib.contextmanager
        #def Warning(self, preference):  # noqa: A003
        #    pap = self.WarningPreference
        #    self.WarningPreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.WarningPreference = pap

        value = ps.VerbosePreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.SilentlyContinue)

        #@VerbosePreference.setter
        #def VerbosePreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("VerbosePreference", value)
        #    self.VerbosePreference

        #@contextlib.contextmanager
        #def Verbose(self, preference):
        #    pap = self.VerbosePreference
        #    self.VerbosePreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.VerbosePreference = pap

        value = ps.DebugPreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.SilentlyContinue)

        #@DebugPreference.setter
        #def DebugPreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("DebugPreference", value)
        #    self.DebugPreference

        #@contextlib.contextmanager
        #def Debug(self, preference):
        #    pap = self.DebugPreference
        #    self.DebugPreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.DebugPreference = pap

        value = ps.InformationPreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.SilentlyContinue)

        #@InformationPreference.setter
        #def InformationPreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("InformationPreference", value)
        #    self.InformationPreference

        #@contextlib.contextmanager
        #def Information(self, preference):
        #    pap = self.InformationPreference
        #    self.InformationPreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.InformationPreference = pap

        value = ps.ProgressPreference
        self.assertIsInstance(value, self.Automation.ActionPreference)
        self.assertEqual(value, self.Automation.ActionPreference.Continue)

        #@ProgressPreference.setter
        #def ProgressPreference(self, value):
        #    self.Runspace.SessionStateProxy.SetVariable("ProgressPreference", value)
        #    self.ProgressPreference

        #@contextlib.contextmanager
        #def Progress(self, preference):
        #    pap = self.ProgressPreference
        #    self.ProgressPreference = preference
        #    try:
        #        yield
        #    finally:
        #        self.ProgressPreference = pap

    def test_special_folders(self):
        ps = self.ps

        # Special Folders

        folder_path = ps.WindowsPath

        folder_path = ps.WindowsSystemPath

        folder_path = ps.UserProfilePath

        folder_path = ps.DesktopPath

        folder_path = ps.ProgramsPath

        folder_path = ps.StartMenuPath

        folder_path = ps.StartupPath

        folder_path = ps.LocalApplicationDataPath

        folder_path = ps.ApplicationDataPath

        folder_path = ps.CommonDesktopPath

        folder_path = ps.CommonProgramsPath

        folder_path = ps.CommonStartMenuPath

        folder_path = ps.CommonStartupPath

        folder_path = ps.CommonApplicationDataPath

    def test_current_user_info(self):
        ps = self.ps

        # Current user info

        current_user = ps.CurrentUser

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
        ps.Write_Output("Write_Output !!!")
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
