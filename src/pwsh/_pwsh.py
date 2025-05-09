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
from nocasedict import NocaseDict
from zope.proxy import ProxyBase, non_overridable          # noqa: F401
from zope.proxy import getProxiedObject, setProxiedObject  # noqa: F401
from tqdm import tqdm  # noqa: F401
from colored import cprint

from ._adict   import adict, defaultadict
from ._epath   import Path
from ._modpath import module_path as _mpath

clr.AddReference("System.ServiceProcess")
sys.path.append(str(pathlib.Path(__file__).resolve().parent/"lib"))
clr.AddReference("System.Management.Automation")
clr.AddReference("Microsoft.Management.Infrastructure")
from System.Management import Automation                           # noqa: E402
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
        """Initialize"""
        self.name  = name
        self._inst = None
        self._flat = flatten_result
        self._cust = customize_result

    def __get__(self, instance, owner):
        """???"""
        self._inst = instance
        return self

    def __call__(self, **kwargs):
        """Call"""
        result = self._inst.cmd(self.name, **kwargs)
        if self._flat: result = self._inst.flatten_result(result)
        return self._cust(self._inst, result)


@public
class PowerShell(ProxyBase):
    """Poweshell API"""

    def __new__(cls, obj=None):
        self = super().__new__(cls,
                               Automation.PowerShell.Create()
                               if obj is None else obj)
        if obj is None:
            self.ErrorActionPreference = "Stop"

            # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/
            #         about/about_redirection?view=powershell-5.1
            # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/
            #         about/about_output_streams?view=powershell-5.1

            # Stream         Stream #  Write Cmdlet
            # -------------------------------------
            # output stream  1         Write-Output
            # Error          2         Write-Error
            # Warning        3         Write-Warning
            # Verbose        4         Write-Verbose
            # Debug          5         Write-Debug
            # Information    6         Write-Information, Write-Host
            # Progress       n/a       Write-Progress

            # preinit of variables for event handler for the event on each relevant stream
            self.ErrorActionPreference
            self.WarningPreference
            self.VerbosePreference
            self.DebugPreference
            self.InformationPreference
            self.ProgressPreference
            # register event handler for the DataAdded event on each relevant stream collection
            streams = self.Streams
            # streams.Error.DataAdded     += self._stream_output_event
            streams.Warning.DataAdded     += self._stream_output_event
            streams.Verbose.DataAdded     += self._stream_output_event
            streams.Debug.DataAdded       += self._stream_output_event
            streams.Information.DataAdded += self._stream_output_event
            streams.Progress.DataAdded    += self._stream_output_event
            # create a data collection for standard output and register the event handler on that
            output_collection = Automation.PSDataCollection[PSObject]()  # .__overloads__
            output_collection.DataAdded   += self._stream_output_event
            cprint("", end="")

        self.env = Env()
        self.env.update(_inst=self)

        return self

    def _stream_output_event(self, sender: System.Object,
                             event_args: Automation.DataAddedEventArgs):
        for item in sender.ReadAll():
            if isinstance(item, Automation.ErrorRecord):  # NOK !!!
                print(f"ErrorRecord: {item}", end=" ", flush=True)
                if False:
                    message = item.ErrorDetails.Message or item.Exception.Message
                    cprint(message, flush=True, fore_256="red")
            elif isinstance(item, Automation.WarningRecord):
                if self._WarningPreference != Automation.ActionPreference.SilentlyContinue:
                    cprint(f"WARNING: {item.Message}", flush=True, fore_256="light_yellow")
            elif isinstance(item, Automation.VerboseRecord):
                if self._VerbosePreference != Automation.ActionPreference.SilentlyContinue:
                    cprint(f"VERBOSE: {item.Message}", flush=True, fore_256="light_yellow")
            elif isinstance(item, Automation.DebugRecord):
                if self._DebugPreference != Automation.ActionPreference.SilentlyContinue:
                    cprint(f"DEBUG: {item.Message}", flush=True, fore_256="light_yellow")
            elif isinstance(item, Automation.InformationRecord):
                if self._InformationPreference != Automation.ActionPreference.SilentlyContinue:
                    if isinstance(item.MessageData, Automation.HostInformationMessage):
                        cprint(f"{item.MessageData.Message}", flush=True,
                            fore_256=self._console_color2color[item.MessageData.ForegroundColor],
                            back_256=self._console_color2color[item.MessageData.BackgroundColor],
                            end="" if item.MessageData.NoNewLine else None)
                    else:
                        cprint(f"{item.MessageData}", flush=True)
            elif isinstance(item, Automation.ProgressRecord):  # NOK !!!
                if self._ProgressPreference != Automation.ActionPreference.SilentlyContinue:
                    cprint("\b" * 1000 + f"{item.Activity}, {item.StatusDescription}", end="",
                           flush=True, fore_256="light_yellow", back_256="dark_cyan")
                    # 'Activity', 'CurrentOperation', 'ParentActivityId', 'PercentComplete',
                    # 'RecordType', 'SecondsRemaining', 'StatusDescription',
                    # 'ActivityId' (only for reading), 'ToString()'
                    # print("CurrentOperation:",  item.CurrentOperation,  " ;",
                    #       "PercentComplete:",   item.PercentComplete,   " ;",
                    #       "RecordType:",        item.RecordType,        " ;",
                    #       "StatusDescription:", item.StatusDescription)
                    # print("ToString():",        item.ToString())
                    # ps.Write_Progress("Write_Progress !!!",
                    #                   Status=f"{i}% Complete:", PercentComplete=i)
            else:  # NOK !!!
                print(f"UnknownRecord[{type(item)}]: {item}", dir(item), flush=True)

    _console_color2color = {
        None: None,
        System.ConsoleColor.Black: "black",
        System.ConsoleColor.DarkBlue: "dark_blue",
        System.ConsoleColor.DarkGreen: "dark_green",
        System.ConsoleColor.DarkCyan: "dark_cyan",
        System.ConsoleColor.DarkRed: "dark_red_1",
        System.ConsoleColor.DarkMagenta: "dark_magenta_1",
        System.ConsoleColor.DarkYellow: "yellow_4a",
        System.ConsoleColor.Gray: "light_gray",
        System.ConsoleColor.DarkGray: "dark_gray",
        System.ConsoleColor.Blue: "blue",
        System.ConsoleColor.Green: "green",
        System.ConsoleColor.Cyan: "cyan",
        System.ConsoleColor.Red: "red",
        System.ConsoleColor.Magenta: "magenta",
        System.ConsoleColor.Yellow: "yellow",
        System.ConsoleColor.White: "white",
    }

    def __init__(self, obj=None):
        """Initialize"""
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
    def Host(self):
        return self.Runspace.SessionStateProxy.GetVariable("Host")

    @property
    def Error(self):
        return self.Runspace.SessionStateProxy.GetVariable("Error")

    @property
    def ErrorView(self):
        return self.Runspace.SessionStateProxy.GetVariable("ErrorView")

    @ErrorView.setter
    def ErrorView(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ErrorView", value)

    @property
    def ErrorActionPreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("ErrorActionPreference")
        self._ErrorActionPreference = result
        return result

    @ErrorActionPreference.setter
    def ErrorActionPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ErrorActionPreference", value)
        self.ErrorActionPreference

    @contextlib.contextmanager
    def ErrorAction(self, preference):
        eap = self.ErrorActionPreference
        self.ErrorActionPreference = preference
        try:
            yield
        finally:
            self.ErrorActionPreference = eap

    @property
    def WarningPreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("WarningPreference")
        self._WarningPreference = result
        return result

    @WarningPreference.setter
    def WarningPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("WarningPreference", value)
        self.WarningPreference

    @contextlib.contextmanager
    def Warning(self, preference):  # noqa: A003
        pap = self.WarningPreference
        self.WarningPreference = preference
        try:
            yield
        finally:
            self.WarningPreference = pap

    @property
    def VerbosePreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("VerbosePreference")
        self._VerbosePreference = result
        return result

    @VerbosePreference.setter
    def VerbosePreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("VerbosePreference", value)
        self.VerbosePreference

    @contextlib.contextmanager
    def Verbose(self, preference):
        pap = self.VerbosePreference
        self.VerbosePreference = preference
        try:
            yield
        finally:
            self.VerbosePreference = pap

    @property
    def DebugPreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("DebugPreference")
        self._DebugPreference = result
        return result

    @DebugPreference.setter
    def DebugPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("DebugPreference", value)
        self.DebugPreference

    @contextlib.contextmanager
    def Debug(self, preference):
        pap = self.DebugPreference
        self.DebugPreference = preference
        try:
            yield
        finally:
            self.DebugPreference = pap

    @property
    def InformationPreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("InformationPreference")
        self._InformationPreference = result
        return result

    @InformationPreference.setter
    def InformationPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("InformationPreference", value)
        self.InformationPreference

    @contextlib.contextmanager
    def Information(self, preference):
        pap = self.InformationPreference
        self.InformationPreference = preference
        try:
            yield
        finally:
            self.InformationPreference = pap

    @property
    def ProgressPreference(self):
        result = self.Runspace.SessionStateProxy.GetVariable("ProgressPreference")
        self._ProgressPreference = result
        return result

    @ProgressPreference.setter
    def ProgressPreference(self, value):
        self.Runspace.SessionStateProxy.SetVariable("ProgressPreference", value)
        self.ProgressPreference

    @contextlib.contextmanager
    def Progress(self, preference):
        pap = self.ProgressPreference
        self.ProgressPreference = preference
        try:
            yield
        finally:
            self.ProgressPreference = pap

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
    _Stop_Process = CmdLet("Stop-Process")

    def Stop_Process(self, **kwargs):
        Force = kwargs.pop("Force", True)
        return self._Stop_Process(Force=Force, **kwargs)

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
        preference = self._customize_ActionPreference(kwargs.get("InformationAction",
                                                      Automation.ActionPreference.Continue))
        if preference == Automation.ActionPreference.Ignore:
            preference = Automation.ActionPreference.SilentlyContinue
        elif preference == Automation.ActionPreference.SilentlyContinue:
            preference = Automation.ActionPreference.Continue
        with self.Information(preference):
            return self._Write_Host(Object=Object, **kwargs)

    _Write_Information = CmdLet("Write-Information", flatten_result=True)

    def Write_Information(self, Msg, **kwargs):
        preference = self._customize_ActionPreference(kwargs.get("InformationAction",
                                                                 self.InformationPreference))
        with self.Information(preference):
            return self._Write_Information(Msg=Msg, **kwargs)

    _Write_Warning = CmdLet("Write-Warning", flatten_result=True)

    def Write_Warning(self, Msg, **kwargs):
        preference = self._customize_ActionPreference(kwargs.get("WarningAction",
                                                                 self.WarningPreference))
        with self.Warning(preference):
            return self._Write_Warning(Msg=Msg, **kwargs)

    _Write_Error = CmdLet("Write-Error", flatten_result=True)

    def Write_Error(self, Msg, **kwargs):
        return self._Write_Error(Msg=Msg, **kwargs)

    _Write_Verbose = CmdLet("Write-Verbose", flatten_result=True)

    def Write_Verbose(self, Msg, **kwargs):
        preference = (self.VerbosePreference if "Verbose" not in kwargs else
                      Automation.ActionPreference.Continue if kwargs["Verbose"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Verbose(preference):
            return self._Write_Verbose(Msg=Msg, **kwargs)

    _Write_Debug = CmdLet("Write-Debug", flatten_result=True)

    def Write_Debug(self, Msg, **kwargs):
        preference = (self.DebugPreference if "Debug" not in kwargs else
                      Automation.ActionPreference.Inquire if kwargs["Debug"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Debug(preference):
            return self._Write_Debug(Msg=Msg, **kwargs)

    _Write_Progress = CmdLet("Write-Progress", flatten_result=True)

    def Write_Progress(self, Activity, **kwargs):
        preference = self.ProgressPreference
        with self.Progress(preference):
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

    @classmethod
    def _customize_ActionPreference(cls, preference):
        if isinstance(preference, Automation.ActionPreference):
            return preference
        elif (isinstance(preference, int)
              or (isinstance(preference, str) and preference.isdigit())):
            return Automation.ActionPreference(int(preference))
        elif isinstance(preference, str) and not preference.isdigit():
            return cls._map_action_preference[preference]
        return preference

    _map_action_preference = NocaseDict({
        # Ignore this event and continue
        "SilentlyContinue": Automation.ActionPreference.SilentlyContinue,
        # Stop the command
        "Stop":             Automation.ActionPreference.Stop,
        # Handle this event as normal and continue
        "Continue":         Automation.ActionPreference.Continue,
        # Ask whether to stop or continue
        "Inquire":          Automation.ActionPreference.Inquire,
        # Ignore the event completely (not even logging it to the target stream)
        "Ignore":           Automation.ActionPreference.Ignore,
        # Reserved for future use.
        "Suspend":          Automation.ActionPreference.Suspend,
        # Enter the debugger. (only for Powershell 7
        # "Break":          Automation.ActionPreference.Break,
    })

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
