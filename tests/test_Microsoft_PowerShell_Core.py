# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

import unittest
from pathlib import Path
import os, shutil, tempfile

from .test_main import PowerShellTestCase
from .test_main import pprint, here, data_dir


class Microsoft_PowerShell_Core_TestCase(PowerShellTestCase):

    def test_main(self):
        ps = self.ps

        # Microsoft.PowerShell.Core

        ps.Import_Module#()
        ps.New_Module#()

        modules = ps.Get_Module(ListAvailable=True)
        self.assertTrue(bool(modules))

        ps.Remove_Module#()

        pwsh = ps.Get_Command(CommandType="Application",
                              Name="powershell.exe", TotalCount=1, EA="0")
        pwsh = Path(pwsh[0].Path) if pwsh else None
        self.assertTrue(bool(pwsh))
        unkn = ps.Get_Command(CommandType="Application",
                              Name="_unknows_executable_.exe", EA="0")
        unkn = Path(unkn[0].Path) if unkn else None
        self.assertFalse(bool(unkn))

        ps.Invoke_Command#()

        ps.ForEach_Object#()

        ps.Where_Object#()

        ps.Start_Job#()
        ps.Stop_Job#()
        ps.Get_Job#()

        ps.Clear_Host#()

        ps.Get_Help#()
        ps.Update_Help#()
        ps.Save_Help#()
