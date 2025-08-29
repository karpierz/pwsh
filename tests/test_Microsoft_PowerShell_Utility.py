# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

import unittest
from pathlib import Path
import os, shutil, tempfile

from .test_main import PowerShellTestCase
from .test_main import pprint, here, data_dir


class Microsoft_PowerShell_Utility_TestCase(PowerShellTestCase):

    def test_main(self):
        ps = self.ps

        # Microsoft.PowerShell.Utility

        ps.Get_Verb#()

        ps.Get_UICulture#()

        ps.Get_Error#()

        ps.Get_Host#()

        ps.Get_Date#()
        ps.Set_Date#()

        ps.Get_FileHash#()

        ps.New_Variable#()
        ps.Get_Variable#()
        ps.Set_Variable#()
        ps.Clear_Variable#()
        ps.Remove_Variable#()

        ps.Invoke_Expression#()

        ps.Add_Type#()

        ps.New_Object#()
        ps.Select_Object#()
        ps.Get_Member#()
        ps.Add_Member#()

        ps.Set_Alias#()

        ps.Format_Hex#()
        ps.Format_List#()
        ps.Format_Table#()
        ps.Format_Wide#()
        ps.Format_Custom#()

        ps.ConvertTo_Csv#()
        ps.ConvertFrom_Csv#()
        ps.Export_Csv#()
        ps.Import_Csv#()

        ps.Test_Json#()
        ps.ConvertTo_Json#()
        ps.ConvertFrom_Json#()

        ps.ConvertTo_Xml#()
        ps.Export_Clixml#()
        ps.Import_Clixml#()

        ps.ConvertTo_Html#()

        ps.Measure_Object#()

        ps.Invoke_WebRequest#()
        ps.Invoke_RestMethod#()

        ps.Start_Sleep#()

        ps.Clear_RecycleBin#()

        ps.Write_Host#()
        ps.Write_Information#()
        ps.Write_Warning#()
        ps.Write_Error#()
        ps.Write_Verbose#()
        ps.Write_Debug#()
        ps.Write_Progress#()
        ps.Write_Output#()

        ps.Read_Host#()
