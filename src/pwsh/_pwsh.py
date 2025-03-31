# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

from typing import Dict
import sys
import os
import pathlib
import contextlib
from enum import IntEnum
from collections import defaultdict
import clr
import System
from System.Collections.Generic import Dictionary
from System.Collections import Hashtable

from public import public
from zope.proxy import ProxyBase, non_overridable          # noqa: F401
from zope.proxy import getProxiedObject, setProxiedObject  # noqa: F401

from ._adict   import adict, defaultadict
from ._epath   import Path
from ._modpath import module_path as _mpath

clr.AddReference("System.ServiceProcess")
sys.path.append(str(pathlib.Path(__file__).resolve().parent/"lib"))
clr.AddReference("System.Management.Automation")
clr.AddReference("Microsoft.Management.Infrastructure")
from System.Management.Automation import PSObject, PSCustomObject  # noqa: E402
# from System.Management.Automation.Language import Parser         # noqa: E402
# from Microsoft.Management.Infrastructure import *                # noqa: E402

public(adict        = adict)
public(defaultadict = defaultadict)
public(Path         = Path)

public(PSObject       = PSObject)
public(PSCustomObject = PSCustomObject)


@public
def module_path(*args, **kwargs):
    return Path(_mpath(*args, level=kwargs.pop("level", 1) + 1, **kwargs))


class PSCustomObjectProxy(ProxyBase):

    def __getattr__(self, name):
        """???"""
        return self.Members[name].Value

    def __getitem__(self, key):
        """???"""
        return self.Members[key].Value


class Env(adict):

    path_keys = {pkey.lower() for pkey in (
                 "SystemDrive", "SystemRoot", "WinDir", "TEMP", "TMP",
                 "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
                 "ProgramData", "APPDATA", "UserProfile", "HOME")}

    def __getitem__(self, key):
        """???"""
        value = super().get("_inst").Get_Content(Path=rf"env:\{key}", EA="0")
        if not value: return None
        return Path(value[0]) if key.lower() in Env.path_keys else value[0]

    def __setitem__(self, key, value):
        """???"""
        if value is None:
            super().get("_inst").Set_Content(Path=rf"env:\{key}", Value=value)
        else:
            super().get("_inst").Set_Content(Path=rf"env:\{key}", Value=value)


@public
class CmdLet:

    def __init__(self, name: str, *,
                 flatten_result: bool = False,
                 customize_result = lambda self, result: result):
        """???"""
        self.name  = name
        self._inst = None
        self._flat = flatten_result
        self._cust = customize_result

    def __get__(self, instance, owner):
        """???"""
        self._inst = instance
        return self

    def __call__(self, **kwargs):
        """???"""
        result = self._inst.cmd(self.name, **kwargs)
        if self._flat: result = self._inst.flatten_result(result)
        return self._cust(self._inst, result)


@public
class PowerShell(ProxyBase):
    """Poweshell API"""

    def __new__(cls, obj=None):
        self = super().__new__(cls,
                               System.Management.Automation.PowerShell.Create()
                               if obj is None else obj)
        if obj is None:
            self.ErrorActionPreference = "Stop"
        self.env = Env()
        self.env.update(_inst=self)
        return self

    def __init__(self, obj=None):
        """???"""
        super().__init__(getProxiedObject(self) if obj is None else obj)

    class Exception(Exception):  # noqa: A001,N818
        """PowerShell error."""

    def Throw(self, expression=None):
        if expression is not None:
            self.cmd("Invoke-Expression", Command=f'throw "{expression}"')
            raise self.Exception(f"{expression}")
        else:
            self.cmd("Invoke-Expression", Command="throw")
            raise self.Exception("ScriptHalted")

    @property
    def Error(self):
        return self.Runspace.SessionStateProxy.GetVariable("Error")

    @property
    def ErrorActionPreference(self):
        return self.Runspace.SessionStateProxy.GetVariable("ErrorActionPreference")

    @ErrorActionPreference.setter
    def ErrorActionPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ErrorActionPreference", value)

    @contextlib.contextmanager
    def ErrorAction(self, preference):
        eap = ps.ErrorActionPreference
        ps.ErrorActionPreference = preference
        try:
            yield
        finally:
            ps.ErrorActionPreference = eap

    @property
    def ErrorView(self):
        return self.Runspace.SessionStateProxy.GetVariable("ErrorView")

    @ErrorView.setter
    def ErrorView(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ErrorView", value)

    @property
    def ProgressPreference(self):
        return self.Runspace.SessionStateProxy.GetVariable("ProgressPreference")

    @ProgressPreference.setter
    def ProgressPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ProgressPreference", value)

    @contextlib.contextmanager
    def Progress(self, preference):
        pap = ps.ProgressPreference
        ps.ProgressPreference = preference
        try:
            yield
        finally:
            ps.ProgressPreference = pap

    @property
    def InformationPreference(self):
        return self.Runspace.SessionStateProxy.GetVariable("InformationPreference")

    @InformationPreference.setter
    def InformationPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("InformationPreference", value)

    @property
    def VerbosePreference(self):
        return self.Runspace.SessionStateProxy.GetVariable("VerbosePreference")

    @VerbosePreference.setter
    def VerbosePreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("VerbosePreference", value)

    @property
    def WarningPreference(self):
        return self.Runspace.SessionStateProxy.GetVariable("WarningPreference")

    @WarningPreference.setter
    def WarningPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("WarningPreference", value)

    def cmd(self, cmd, **kwargs):
        cmd = self.AddCommand(cmd)
        for key, val in kwargs.items():
            if isinstance(val, bool) and val:
                cmd.AddParameter(key)
            else:
                cmd.AddParameter(key, self._customize_param(val))
        result = self.Invoke()
        self.Commands.Clear()
        return [(self._customize_result(item)
                 if item is not None else None) for item in result]

    # Special Folders

    @property
    def WindowsPath(self) -> Path:
        kind = System.Environment.SpecialFolder.Windows
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def WindowsSystemPath(self) -> Path:
        kind = System.Environment.SpecialFolder.System
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def UserProfilePath(self) -> Path:
        kind = System.Environment.SpecialFolder.UserProfile
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def DesktopPath(self) -> Path:
        kind = System.Environment.SpecialFolder.DesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def ProgramsPath(self) -> Path:
        kind = System.Environment.SpecialFolder.Programs
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def StartMenuPath(self) -> Path:
        kind = System.Environment.SpecialFolder.StartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def StartupPath(self) -> Path:
        kind = System.Environment.SpecialFolder.Startup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def LocalApplicationDataPath(self) -> Path:
        kind = System.Environment.SpecialFolder.LocalApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def ApplicationDataPath(self) -> Path:
        kind = System.Environment.SpecialFolder.ApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonDesktopPath(self) -> Path:
        kind = System.Environment.SpecialFolder.CommonDesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonProgramsPath(self) -> Path:
        kind = System.Environment.SpecialFolder.CommonPrograms
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonStartMenuPath(self) -> Path:
        kind = System.Environment.SpecialFolder.CommonStartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonStartupPath(self) -> Path:
        kind = System.Environment.SpecialFolder.CommonStartup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonApplicationDataPath(self) -> Path:
        kind = System.Environment.SpecialFolder.CommonApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CurrentUser(self) -> object:
        from System.Security.Principal import WindowsIdentity
        current_user = WindowsIdentity.GetCurrent()
        current_user.NetId = current_user.Name.split("\\")[1]
        if not hasattr(current_user.__class__, "FullName"):
            def FullName(self) -> str:
                ad_parts = []
                with contextlib.suppress(Exception):
                    user_info = self._current_user_data(
                                    self._EXTENDED_NAME_FORMAT.NameFullyQualifiedDN)
                    ad_parts  = [part.replace("\0", ",").strip().partition("=")
                                 for part in user_info.replace(r"\,", "\0").split(",")]
                full_name = next((value.strip() for key, sep, value in ad_parts
                                  if sep and key.strip().upper() == "CN"), None)
                is_full_name = full_name is not None
                if not is_full_name:
                    full_name = current_user.UPN.rsplit("@", maxsplit=1)[0]
                return " ".join((item.strip()
                                 for item in reversed(full_name.split(",", maxsplit=1)))
                                if is_full_name else
                                (item.strip().capitalize()
                                 for item in full_name.rsplit(".", maxsplit=1))).strip()
            current_user.__class__.FullName = property(FullName)
        if not hasattr(current_user.__class__, "IsAdmin"):
            def IsAdmin(self) -> bool:
                from System.Security.Principal import WindowsPrincipal, WindowsBuiltInRole
                principal = WindowsPrincipal(self)
                return principal and bool(principal.IsInRole(WindowsBuiltInRole.Administrator))
            current_user.__class__.IsAdmin = property(IsAdmin)
        if not hasattr(current_user.__class__, "UPN"):
            def UPN(self) -> str:
                return self._current_user_data(self._EXTENDED_NAME_FORMAT.NameUserPrincipal)
            current_user.__class__.UPN = property(UPN)
        return current_user

    class _EXTENDED_NAME_FORMAT(IntEnum):
        NameUnknown = 0
        NameFullyQualifiedDN = 1
        NameSamCompatible = 2
        NameDisplay = 3
        NameUniqueId = 6
        NameCanonical = 7
        NameUserPrincipal = 8
        NameCanonicalEx = 9
        NameServicePrincipal = 10
        NameDnsDomain = 12
        NameGivenName = 13
        NameSurname = 14

    @staticmethod
    def _current_user_data(name_format: _EXTENDED_NAME_FORMAT) -> str:
        # https://stackoverflow.com/questions/21766954/how-to-get-windows-users-full-name-in-python
        import ctypes as ct
        GetUserNameEx = ct.windll.secur32.GetUserNameExW

        size = ct.c_ulong(0)
        GetUserNameEx(name_format, None, ct.byref(size))

        name_buffer = ct.create_unicode_buffer(size.value)
        GetUserNameEx(name_format, name_buffer, ct.byref(size))
        return name_buffer.value

    # Microsoft.PowerShell.Core

    Import_Module = CmdLet("Import-Module")
    New_Module    = CmdLet("New-Module")
    Get_Module    = CmdLet("Get-Module")
    Remove_Module = CmdLet("Remove-Module")

    Get_Command    = CmdLet("Get-Command")
    Invoke_Command = CmdLet("Invoke-Command")

    _ForEach_Object = CmdLet("ForEach-Object")

    def ForEach_Object(self, InputObject, **kwargs):
        return self._ForEach_Object(InputObject=InputObject, **kwargs)

    _Where_Object = CmdLet("Where-Object")

    def Where_Object(self, InputObject, **kwargs):
        return self._Where_Object(InputObject=InputObject, **kwargs)

    Start_Job = CmdLet("Start-Job")
    Stop_Job  = CmdLet("Stop-Job")
    Get_Job   = CmdLet("Get-Job")

    Clear_Host = CmdLet("Clear-Host")

    Get_Help    = CmdLet("Get-Help",    flatten_result=True)
    Update_Help = CmdLet("Update-Help", flatten_result=True)
    Save_Help   = CmdLet("Save-Help",   flatten_result=True)

    # Microsoft.PowerShell.Management

    # https://learn.microsoft.com/en-us/powershell/scripting/how-to-use-docs?view=powershell-5.1
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_providers?view=powershell-5.1

    Push_Location = CmdLet("Push-Location")
    Pop_Location  = CmdLet("Pop-Location")

    Get_ChildItem = CmdLet("Get-ChildItem",
        customize_result = lambda self, result: result or [])

    Get_Item    = CmdLet("Get-Item")
    New_Item    = CmdLet("New-Item")
    Set_Item    = CmdLet("Set-Item")
    Copy_Item   = CmdLet("Copy-Item")
    Move_Item   = CmdLet("Move-Item")
    Remove_Item = CmdLet("Remove-Item")
    Rename_Item = CmdLet("Rename-Item")
    Clear_Item  = CmdLet("Clear-Item")

    Get_ItemProperty    = CmdLet("Get-ItemProperty")
    New_ItemProperty    = CmdLet("New-ItemProperty")
    Set_ItemProperty    = CmdLet("Set-ItemProperty")
    Copy_ItemProperty   = CmdLet("Copy-ItemProperty")
    Move_ItemProperty   = CmdLet("Move-ItemProperty")
    Remove_ItemProperty = CmdLet("Remove-ItemProperty", flatten_result=True)
    Rename_ItemProperty = CmdLet("Rename-ItemProperty", flatten_result=True)
    Clear_ItemProperty  = CmdLet("Clear-ItemProperty",  flatten_result=True)

    _Get_ItemPropertyValue = CmdLet("Get-ItemPropertyValue")

    def Get_ItemPropertyValue(self, **kwargs):
        return (self._Get_ItemPropertyValue(**kwargs)
                if self.Get_ItemProperty(**kwargs) else [])

    Test_Path = CmdLet("Test-Path",
        customize_result = lambda self, result: bool(result[0]))

    Convert_Path = CmdLet("Convert-Path")

    Get_Content   = CmdLet("Get-Content")
    Set_Content   = CmdLet("Set-Content")
    Add_Content   = CmdLet("Add-Content")
    Clear_Content = CmdLet("Clear-Content")

    Get_Process   = CmdLet("Get-Process")
    Start_Process = CmdLet("Start-Process")
    Stop_Process  = CmdLet("Stop-Process")

    New_Service   = CmdLet("New-Service", flatten_result=True)
    Get_Service   = CmdLet("Get-Service")
    Start_Service = CmdLet("Start-Service", flatten_result=True)
    Stop_Service  = CmdLet("Stop-Service")

    Get_PSDrive    = CmdLet("Get-PSDrive")
    New_PSDrive    = CmdLet("New-PSDrive",    flatten_result=True)
    Remove_PSDrive = CmdLet("Remove-PSDrive", flatten_result=True)

    Get_WmiObject = CmdLet("Get-WmiObject")

    # Microsoft.PowerShell.Utility

    Get_Verb = CmdLet("Get-Verb")
    # Get-Verb [[-verb] <String[]>]

    Get_UICulture = CmdLet("Get-UICulture", flatten_result=True)

    Get_Error = CmdLet("Get-Error")

    Get_Host = CmdLet("Get-Host")

    Get_Date = CmdLet("Get-Date")
    Set_Date = CmdLet("Set-Date")

    Get_FileHash = CmdLet("Get-FileHash")

    New_Variable    = CmdLet("New-Variable")
    Get_Variable    = CmdLet("Get-Variable")
    Set_Variable    = CmdLet("Set-Variable")
    Clear_Variable  = CmdLet("Clear-Variable")
    Remove_Variable = CmdLet("Remove-Variable")

    Invoke_Expression = CmdLet("Invoke-Expression")
    # Invoke-Expression [-Command] <String> [<CommonParameters>]

    Add_Type = CmdLet("Add-Type")

    New_Object    = CmdLet("New-Object")
    Select_Object = CmdLet("Select-Object")
    Get_Member    = CmdLet("Get-Member")
    Add_Member    = CmdLet("Add-Member")

    Set_Alias = CmdLet("Set-Alias")

    Format_Hex    = CmdLet("Format-Hex")
    Format_List   = CmdLet("Format-List")
    Format_Table  = CmdLet("Format-Table")
    Format_Wide   = CmdLet("Format-Wide")
    Format_Custom = CmdLet("Format-Custom")

    ConvertTo_Csv   = CmdLet("ConvertTo-Csv")
    ConvertFrom_Csv = CmdLet("ConvertFrom-Csv")
    Export_Csv      = CmdLet("Export-Csv")
    Import_Csv      = CmdLet("Import-Csv")

    Test_Json = CmdLet("Test-Json",
        customize_result = lambda self, result: bool(result[0]))
    ConvertTo_Json   = CmdLet("ConvertTo-Json")
    ConvertFrom_Json = CmdLet("ConvertFrom-Json", flatten_result=True)

    ConvertTo_Xml = CmdLet("ConvertTo-Xml")
    Export_Clixml = CmdLet("Export-Clixml")
    Import_Clixml = CmdLet("Import-Clixml")

    ConvertTo_Html = CmdLet("ConvertTo-Html")

    Measure_Object = CmdLet("Measure-Object")

    Invoke_WebRequest = CmdLet("Invoke-WebRequest", flatten_result=True)
    Invoke_RestMethod = CmdLet("Invoke-RestMethod", flatten_result=True)

    Start_Sleep = CmdLet("Start-Sleep")

    Clear_RecycleBin = CmdLet("Clear-RecycleBin")

    _Write_Host = CmdLet("Write-Host", flatten_result=True)

    def Write_Host(self, Object, **kwargs):
        return self._Write_Host(Object=Object, **kwargs)

    _Write_Information = CmdLet("Write-Information", flatten_result=True)

    def Write_Information(self, Msg, **kwargs):
        return self._Write_Information(Msg=Msg, **kwargs)

    _Write_Warning = CmdLet("Write-Warning", flatten_result=True)

    def Write_Warning(self, Msg, **kwargs):
        return self._Write_Warning(Msg=Msg, **kwargs)

    _Write_Error = CmdLet("Write-Error", flatten_result=True)

    def Write_Error(self, Msg, **kwargs):
        return self._Write_Error(Msg=Msg, **kwargs)

    _Write_Verbose = CmdLet("Write-Verbose", flatten_result=True)

    def Write_Verbose(self, Msg, **kwargs):
        return self._Write_Verbose(Msg=Msg, **kwargs)

    _Write_Debug = CmdLet("Write-Debug", flatten_result=True)

    def Write_Debug(self, Msg, **kwargs):
        return self._Write_Debug(Msg=Msg, **kwargs)

    _Write_Progress = CmdLet("Write-Progress", flatten_result=True)

    def Write_Progress(self, Activity, **kwargs):
        return self._Write_Progress(Activity=Activity, **kwargs)

    _Write_Output = CmdLet("Write-Output", flatten_result=True)

    def Write_Output(self, InputObject, **kwargs):
        return self._Write_Output(InputObject=InputObject, **kwargs)

    _Read_Host = CmdLet("Read-Host", flatten_result=True)

    def Read_Host(self, Prompt, **kwargs):
        if Prompt is None:
            return self._Read_Host(**kwargs)
        else:
            return self._Read_Host(Prompt=Prompt, **kwargs)

    # Microsoft.PowerShell.Security

    Get_ExecutionPolicy = CmdLet("Get-ExecutionPolicy")
    Set_ExecutionPolicy = CmdLet("Set-ExecutionPolicy")

    Get_Credential = CmdLet("Get-Credential")

    Get_Acl = CmdLet("Get-Acl")
    Set_Acl = CmdLet("Set-Acl")

    Get_CmsMessage       = CmdLet("Get-CmsMessage")
    Protect_CmsMessage   = CmdLet("Protect-CmsMessage")
    Unprotect_CmsMessage = CmdLet("Unprotect-CmsMessage")

    ConvertTo_SecureString   = CmdLet("ConvertTo-SecureString")
    ConvertFrom_SecureString = CmdLet("ConvertFrom-SecureString")

    Get_PfxCertificate = CmdLet("Get-PfxCertificate")

    Get_AuthenticodeSignature = CmdLet("Get-AuthenticodeSignature")
    Set_AuthenticodeSignature = CmdLet("Set-AuthenticodeSignature")

    New_FileCatalog  = CmdLet("New-FileCatalog")
    Test_FileCatalog = CmdLet("Test-FileCatalog")

    # Microsoft.PowerShell.Host

    Start_Transcript = CmdLet("Start-Transcript")
    Stop_Transcript  = CmdLet("Stop-Transcript")

    # Microsoft.PowerShell.Archive

    Compress_Archive = CmdLet("Compress-Archive")
    Expand_Archive   = CmdLet("Expand-Archive")

    # Microsoft.PowerShell.Diagnostics

    Get_Counter = CmdLet("Get-Counter")

    Get_WinEvent = CmdLet("Get-WinEvent")
    New_WinEvent = CmdLet("New-WinEvent")

    # Module: ThreadJob

    Start_ThreadJob = CmdLet("Start-ThreadJob")

    # Module: DISM

    Get_WindowsOptionalFeature     = CmdLet("Get-WindowsOptionalFeature",
                                            flatten_result=True)
    Enable_WindowsOptionalFeature  = CmdLet("Enable-WindowsOptionalFeature",
                                            flatten_result=True)
    Disable_WindowsOptionalFeature = CmdLet("Disable-WindowsOptionalFeature",
                                            flatten_result=True)

    Add_AppxProvisionedPackage = CmdLet("Add-AppxProvisionedPackage")

    # Module: Appx

    Get_AppxPackage    = CmdLet("Get-AppxPackage")
    Add_AppxPackage    = CmdLet("Add-AppxPackage")
    Remove_AppxPackage = CmdLet("Remove-AppxPackage")

    # Module: CimCmdlets

    New_CimInstance    = CmdLet("New-CimInstance")
    Get_CimInstance    = CmdLet("Get-CimInstance")
    Set_CimInstance    = CmdLet("Set-CimInstance")
    Remove_CimInstance = CmdLet("Remove-CimInstance")
    Invoke_CimMethod   = CmdLet("Invoke-CimMethod")

    # Misc internal utilities

    @staticmethod
    def hashable2dict(hashable: Dictionary) -> dict:
        return {item.Key: item.Value for item in hashable}

    @staticmethod
    def hashable2defaultdict(hashable: Dictionary,
                             default_factory=None) -> defaultdict:
        return defaultdict(default_factory,
                           PowerShell.hashable2dict(hashable))

    @staticmethod
    def hashable2adict(hashable: Dictionary) -> adict:
        return adict(PowerShell.hashable2dict(hashable))

    @staticmethod
    def hashable2defaultadict(hashable: Dictionary,
                              default_factory=None) -> defaultadict:
        return defaultadict(default_factory,
                            PowerShell.hashable2dict(hashable))

    @staticmethod
    def dict2hashtable(dic: Dict) -> Dictionary:
        htable = Hashtable()
        for key, val in dic.items():
            htable[key] = val
        return htable

    @staticmethod
    def flatten_result(result):
        return None if not result else result[0] if len(result) == 1 else result

    @staticmethod
    def _customize_param(val):
        if isinstance(val, os.PathLike):
            return str(val)
        # elif isinstance(val, Dict):
        #     return PowerShell._customize_dict(val)
        else:
            return val

    @staticmethod
    def _customize_dict(dic):
        dic = dic.copy()
        for key, val in dic.items():
            if isinstance(val, os.PathLike):
                dic[key] = str(val)
        return dic

    def _customize_result(self, item):
        if isinstance(item.BaseObject, PSCustomObject):
            item = PSCustomObjectProxy(item)
            item._ps = self
            return item
        else:
            return item.BaseObject


global ps
ps = PowerShell()
ps.Set_ExecutionPolicy(ExecutionPolicy="Bypass", Scope="Process", Force=True)

public(ps = ps)
