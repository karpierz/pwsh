# Copyright (c) 2024 Adam Karpierz
# SPDX-License-Identifier: Zlib

import unittest
from pathlib import Path
import os, shutil, tempfile

from .test_main import PowerShellTestCase
from .test_main import pprint, here, data_dir


class Microsoft_PowerShell_Management_TestCase(PowerShellTestCase):

    def test_main(self):
        ps = self.ps

        # Microsoft.PowerShell.Management

        ps.Push_Location#()
        ps.Pop_Location#()

        ps.Get_ChildItem#()

        ps.Get_Item#()
        ps.New_Item#()
        ps.Set_Item#()
        ps.Copy_Item#()
        ps.Move_Item#()
        ps.Remove_Item#()
        ps.Rename_Item#()
        ps.Clear_Item#()

        ps.Get_ItemProperty#()
        ps.New_ItemProperty#()
        ps.Set_ItemProperty#()
        ps.Copy_ItemProperty#()
        ps.Move_ItemProperty#()
        ps.Remove_ItemProperty#()
        ps.Rename_ItemProperty#()
        ps.Clear_ItemProperty#()

        ps.Get_ItemPropertyValue#()

        ps.Test_Path#()
        ps.Resolve_Path#()
        ps.Convert_Path#()

        ps.Get_Content#()
        ps.Set_Content#()
        ps.Add_Content#()
        ps.Clear_Content#()

        ps.Get_Process#()
        ps.Start_Process#()
        ps.Stop_Process#()

        ps.New_Service#()
        ps.Get_Service#()
        ps.Start_Service#()
        ps.Stop_Service#()

        ps.Get_PSDrive#()
        ps.New_PSDrive#()
        ps.Remove_PSDrive#()

        ps.Get_WmiObject#()
