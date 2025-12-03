# flake8-in-file-ignores: noqa: E402

# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

from typing import TypeAlias, Any
from typing_extensions import Self
from collections.abc import Callable, Iterable, Sequence, Generator
from os import PathLike
import builtins
import sys
import contextlib
from enum import IntEnum
from collections import defaultdict
import clr     # type: ignore[import-untyped]
import System  # type: ignore[import-not-found]
from System import Array, String
from System.Collections.Generic import Dictionary  # type: ignore[import-not-found]
from System.Collections import Hashtable           # type: ignore[import-not-found]

from utlx import public
from nocasedict import NocaseDict
from zope.proxy import (ProxyBase, non_overridable,  # type: ignore[import-untyped]  # noqa: F401
                        getProxiedObject, setProxiedObject)
from tqdm import tqdm  # noqa: F401
from colored import cprint

from utlx import adict, defaultadict
from utlx import Path
from utlx import module_path as _mpath

AnyCallable: TypeAlias = Callable[..., Any]

powershell_path = Path.which("powershell.exe")
if powershell_path is None:
    raise AssertionError("powershell.exe was not found!")

clr.AddReference("System.ServiceProcess")
sys.path.append(str(powershell_path.parent))
sys.path.append(str(Path(__file__).resolve().parent/"lib"))
clr.AddReference("System.Management.Automation")
clr.AddReference("Microsoft.Management.Infrastructure")
from System.Management import Automation           # type: ignore[import-not-found]
from System.Management.Automation import PSObject  # type: ignore[import-not-found]
from System.Management.Automation import PSCustomObject
# from System.Management.Automation.Language import Parser
# from Microsoft.Management.Infrastructure import *

public(adict        = adict)
public(defaultadict = defaultadict)
public(Path         = Path)

public(PSObject       = PSObject)
public(PSCustomObject = PSCustomObject)


@public
def module_path(*args: Any, **kwargs: Any) -> Path:
    return Path(_mpath(*args, level=kwargs.pop("level", 1) + 1, **kwargs))


class PSCustomObjectProxy(ProxyBase):  # type: ignore[misc]

    def __getattr__(self, name: str) -> Any:
        """Attribute access"""
        return self.Members[name].Value

    def __getitem__(self, key: Any) -> Any:
        """Item access"""
        return self.Members[key].Value


class Env(adict):

    path_keys = {pkey.lower() for pkey in (
                 "SystemDrive", "SystemRoot", "WinDir", "TEMP", "TMP",
                 "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
                 "ProgramData", "APPDATA", "UserProfile", "HOME")}

    def __getitem__(self, key: Any) -> Any:
        """Item access"""
        inst = super().__getitem__("_inst")
        value = inst.Get_Content(Path=rf"env:\{key}", EA="0")
        if not value: return None
        return Path(value[0]) if key.lower() in Env.path_keys else value[0]

    def __setitem__(self, key: Any, value: Any) -> None:
        """Item assignment"""
        inst = super().__getitem__("_inst")
        if value is None:
            inst.Set_Content(Path=rf"env:\{key}", Value=value)
        else:
            inst.Set_Content(Path=rf"env:\{key}", Value=value)


@public
class CmdLet:

    def __init__(self, name: str, *,
                 flatten_result: bool = False,
                 customize_result: AnyCallable = lambda self, result: result):
        """Initializer"""
        self.name:  str  = name
        self._inst: Any  = None
        self._flat: bool = flatten_result
        self._cust: AnyCallable = customize_result

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        """Access handler"""
        self._inst = instance
        return self

    def __call__(self, **kwargs: Any) -> Any:
        """Call"""
        result = self._inst.cmd(self.name, **kwargs)
        if self._flat: result = self._inst.flatten_result(result)
        return self._cust(self._inst, result)


@public
class PowerShell(ProxyBase):  # type: ignore[misc]
    """Poweshell API"""

    def __new__(cls, obj: Automation.PowerShell | None = None) -> Self:
        """Constructor"""
        self: PowerShell = super().__new__(cls,
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
        else: pass  # pragma: no cover

        self.env = Env()
        self.env.update(_inst=self)

        return self

    def _stream_output_event(self, sender: System.Object,
                             event_args: Automation.DataAddedEventArgs) -> None:
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

    def __init__(self, obj: Automation.PowerShell | None = None):
        """Initializer"""
        super().__init__(getProxiedObject(self) if obj is None else obj)

    class Exception(builtins.Exception):  # noqa: A001,N818
        """PowerShell error."""

    def Throw(self, expression: Any | None = None) -> None:
        if expression is not None:
            self.cmd("Invoke-Expression", Command=f'throw "{expression}"')
            raise self.Exception(f"{expression}")
        else:
            self.cmd("Invoke-Expression", Command="throw")
            raise self.Exception("ScriptHalted")

    @property
    def Host(self) -> Any:
        return self.Runspace.SessionStateProxy.GetVariable("Host")

    @property
    def Error(self) -> Any:
        return self.Runspace.SessionStateProxy.GetVariable("Error")

    @property
    def ErrorView(self) -> Any:
        return self.Runspace.SessionStateProxy.GetVariable("ErrorView")

    @ErrorView.setter
    def ErrorView(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("ErrorView", value)

    @property
    def ErrorActionPreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("ErrorActionPreference")
        self._ErrorActionPreference = result
        return result

    @ErrorActionPreference.setter
    def ErrorActionPreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("ErrorActionPreference", value)
        self.ErrorActionPreference

    @contextlib.contextmanager
    def ErrorAction(self, preference: Any) -> Generator[None, None, None]:
        eap = self.ErrorActionPreference
        self.ErrorActionPreference = preference
        try:
            yield
        finally:
            self.ErrorActionPreference = eap

    @property
    def WarningPreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("WarningPreference")
        self._WarningPreference = result
        return result

    @WarningPreference.setter
    def WarningPreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("WarningPreference", value)
        self.WarningPreference

    @contextlib.contextmanager
    def Warning(self, preference: Any) -> Generator[None, None, None]:  # noqa: A003
        pap = self.WarningPreference
        self.WarningPreference = preference
        try:
            yield
        finally:
            self.WarningPreference = pap

    @property
    def VerbosePreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("VerbosePreference")
        self._VerbosePreference = result
        return result

    @VerbosePreference.setter
    def VerbosePreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("VerbosePreference", value)
        self.VerbosePreference

    @contextlib.contextmanager
    def Verbose(self, preference: Any) -> Generator[None, None, None]:
        pap = self.VerbosePreference
        self.VerbosePreference = preference
        try:
            yield
        finally:
            self.VerbosePreference = pap

    @property
    def DebugPreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("DebugPreference")
        self._DebugPreference = result
        return result

    @DebugPreference.setter
    def DebugPreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("DebugPreference", value)
        self.DebugPreference

    @contextlib.contextmanager
    def Debug(self, preference: Any) -> Generator[None, None, None]:
        pap = self.DebugPreference
        self.DebugPreference = preference
        try:
            yield
        finally:
            self.DebugPreference = pap

    @property
    def InformationPreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("InformationPreference")
        self._InformationPreference = result
        return result

    @InformationPreference.setter
    def InformationPreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("InformationPreference", value)
        self.InformationPreference

    @contextlib.contextmanager
    def Information(self, preference: Any) -> Generator[None, None, None]:
        pap = self.InformationPreference
        self.InformationPreference = preference
        try:
            yield
        finally:
            self.InformationPreference = pap

    @property
    def ProgressPreference(self) -> Automation.ActionPreference:
        result = self.Runspace.SessionStateProxy.GetVariable("ProgressPreference")
        self._ProgressPreference = result
        return result

    @ProgressPreference.setter
    def ProgressPreference(self, value: Any) -> None:
        self.Runspace.SessionStateProxy.SetVariable("ProgressPreference", value)
        self.ProgressPreference

    @contextlib.contextmanager
    def Progress(self, preference: Any) -> Generator[None, None, None]:
        pap = self.ProgressPreference
        self.ProgressPreference = preference
        try:
            yield
        finally:
            self.ProgressPreference = pap

    def cmd(self, cmd: str | String, **kwargs: Any) -> list[Any]:
        ps_cmd = self.AddCommand(cmd)
        for key, val in kwargs.items():
            if isinstance(val, bool) and val:
                ps_cmd.AddParameter(key)
            else:
                ps_cmd.AddParameter(key, self._customize_param(val))
        result = self.Invoke()
        self.Commands.Clear()
        return [(self._customize_result(item)
                 if item is not None else None) for item in result]

    # Special Folders

    @property
    def WindowsPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.Windows
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def WindowsSystemPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.System
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def UserProfilePath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.UserProfile
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def DesktopPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.DesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def ProgramsPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.Programs
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def StartMenuPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.StartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def StartupPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.Startup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def LocalApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.LocalApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def ApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.ApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonDesktopPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonDesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonProgramsPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonPrograms
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonStartMenuPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonStartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonStartupPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonStartup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    @property
    def CommonApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result is not None else None

    # Current user info

    @property
    def CurrentUser(self) -> object:
        from System.Security.Principal import WindowsIdentity  # type: ignore[import-not-found]
        current_user = WindowsIdentity.GetCurrent()
        current_user.NetId = current_user.Name.split("\\")[1]
        _current_user_data    = self._current_user_data
        _EXTENDED_NAME_FORMAT = self._EXTENDED_NAME_FORMAT
        if not hasattr(current_user.__class__, "FullName"):
            def FullName(self: object) -> str:
                ad_parts = []
                with contextlib.suppress(builtins.Exception):
                    user_info = _current_user_data(
                                    _EXTENDED_NAME_FORMAT.NameFullyQualifiedDN)
                    ad_parts  = [part.replace("\0", ",").strip().partition("=")
                                 for part in user_info.replace(r"\,", "\0").split(",")]
                try:
                    full_name = next((value.strip() for key, sep, value in ad_parts
                                      if sep and key.strip().upper() == "CN"))
                    name_parts = (item.strip()
                                  for item in reversed(full_name.split(",", maxsplit=1)))
                except StopIteration:
                    full_name = current_user.UPN.rsplit("@", maxsplit=1)[0]
                    name_parts = (item.strip().capitalize()
                                  for item in full_name.rsplit(".", maxsplit=1))
                return " ".join(name_parts).strip()
            current_user.__class__.FullName = property(FullName)
        if not hasattr(current_user.__class__, "IsAdmin"):
            def IsAdmin(self: object) -> bool:
                from System.Security.Principal import WindowsPrincipal, WindowsBuiltInRole
                principal = WindowsPrincipal(self)
                return principal and bool(principal.IsInRole(WindowsBuiltInRole.Administrator))
            current_user.__class__.IsAdmin = property(IsAdmin)
        if not hasattr(current_user.__class__, "UPN"):
            def UPN(self: object) -> str:
                return _current_user_data(_EXTENDED_NAME_FORMAT.NameUserPrincipal)
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

    def ForEach_Object(self, InputObject: Any, **kwargs: Any) -> Any:
        return self._ForEach_Object(InputObject=InputObject, **kwargs)

    _Where_Object = CmdLet("Where-Object")

    def Where_Object(self, InputObject: Any, **kwargs: Any) -> Any:
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

    def Get_ItemPropertyValue(self, **kwargs: Any) -> Iterable[Any]:
        return (self._Get_ItemPropertyValue(**kwargs)
                if self.Get_ItemProperty(**kwargs) else [])

    Test_Path = CmdLet("Test-Path",
        customize_result = lambda self, result: bool(result[0]))
    Resolve_Path = CmdLet("Resolve-Path")
    Convert_Path = CmdLet("Convert-Path")

    Get_Content   = CmdLet("Get-Content")
    Set_Content   = CmdLet("Set-Content")
    Add_Content   = CmdLet("Add-Content")
    Clear_Content = CmdLet("Clear-Content")

    Get_Process    = CmdLet("Get-Process")
    _Start_Process = CmdLet("Start-Process")
    _Stop_Process  = CmdLet("Stop-Process")

    def Start_Process(self, **kwargs: Any) -> Any:
        kwargs = kwargs.copy()
        if "ArgumentList" in kwargs:
            kwargs["ArgumentList"] = Array[String](kwargs["ArgumentList"])
        return self._Start_Process(**kwargs)

    def Stop_Process(self, **kwargs: Any) -> Any:
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

    Select_String = CmdLet("Select-String")  # , flatten_result=True)

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

    def Write_Host(self, Object: Any, **kwargs: Any) -> Any:
        preference = self._customize_ActionPreference(kwargs.get("InformationAction",
                                                      Automation.ActionPreference.Continue))
        if preference == Automation.ActionPreference.Ignore:
            preference = Automation.ActionPreference.SilentlyContinue
        elif preference == Automation.ActionPreference.SilentlyContinue:
            preference = Automation.ActionPreference.Continue
        with self.Information(preference):
            return self._Write_Host(Object=Object, **kwargs)

    _Write_Information = CmdLet("Write-Information", flatten_result=True)

    def Write_Information(self, Msg: Any, **kwargs: Any) -> Any:
        preference = self._customize_ActionPreference(kwargs.get("InformationAction",
                                                                 self.InformationPreference))
        with self.Information(preference):
            return self._Write_Information(Msg=Msg, **kwargs)

    _Write_Warning = CmdLet("Write-Warning", flatten_result=True)

    def Write_Warning(self, Msg: Any, **kwargs: Any) -> Any:
        preference = self._customize_ActionPreference(kwargs.get("WarningAction",
                                                                 self.WarningPreference))
        with self.Warning(preference):
            return self._Write_Warning(Msg=Msg, **kwargs)

    _Write_Error = CmdLet("Write-Error", flatten_result=True)

    def Write_Error(self, Msg: Any, **kwargs: Any) -> Any:
        return self._Write_Error(Msg=Msg, **kwargs)

    _Write_Verbose = CmdLet("Write-Verbose", flatten_result=True)

    def Write_Verbose(self, Msg: Any, **kwargs: Any) -> Any:
        preference = (self.VerbosePreference if "Verbose" not in kwargs else
                      Automation.ActionPreference.Continue if kwargs["Verbose"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Verbose(preference):
            return self._Write_Verbose(Msg=Msg, **kwargs)

    _Write_Debug = CmdLet("Write-Debug", flatten_result=True)

    def Write_Debug(self, Msg: Any, **kwargs: Any) -> Any:
        preference = (self.DebugPreference if "Debug" not in kwargs else
                      Automation.ActionPreference.Inquire if kwargs["Debug"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Debug(preference):
            return self._Write_Debug(Msg=Msg, **kwargs)

    _Write_Progress = CmdLet("Write-Progress", flatten_result=True)

    def Write_Progress(self, Activity: Any, **kwargs: Any) -> Any:
        preference = self.ProgressPreference
        with self.Progress(preference):
            return self._Write_Progress(Activity=Activity, **kwargs)

    _Write_Output = CmdLet("Write-Output", flatten_result=True)

    def Write_Output(self, InputObject: Any, **kwargs: Any) -> Any:
        return self._Write_Output(InputObject=InputObject, **kwargs)

    _Read_Host = CmdLet("Read-Host", flatten_result=True)

    def Read_Host(self, Prompt: Any, **kwargs: Any) -> Any:
        if Prompt is None:
            return self._Read_Host(**kwargs)
        else:
            return self._Read_Host(Prompt=Prompt, **kwargs)

    @classmethod
    def _customize_ActionPreference(cls, preference: Any) -> Any:
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
    def hashable2dict(hashable: Dictionary) -> dict[Any, Any]:
        return {item.Key: item.Value for item in hashable}

    @staticmethod
    def hashable2defaultdict(hashable: Dictionary,
                             default_factory: AnyCallable | None = None) \
                             -> defaultdict[Any, Any]:
        return defaultdict(default_factory, PowerShell.hashable2dict(hashable))

    @staticmethod
    def hashable2adict(hashable: Dictionary) -> adict:
        return adict(PowerShell.hashable2dict(hashable))

    @staticmethod
    def hashable2defaultadict(hashable: Dictionary,
                              default_factory: AnyCallable | None = None) \
                              -> defaultadict:
        return defaultadict(default_factory, PowerShell.hashable2dict(hashable))

    @staticmethod
    def dict2hashtable(dic: dict[Any, Any]) -> Dictionary:
        htable = Hashtable()
        for key, val in dic.items():
            htable[key] = val
        return htable

    @staticmethod
    def flatten_result(result: Sequence[Any] | None) -> Any:
        return None if not result else result[0] if len(result) == 1 else result

    @staticmethod
    def _customize_param(val: Any) -> Any:
        if isinstance(val, PathLike):
            return str(val)
        # elif isinstance(val, dict):
        #     return PowerShell._customize_dict(val)
        else:
            return val

    @staticmethod
    def _customize_dict(dic: dict[Any, Any]) -> dict[Any, Any]:
        dic = dic.copy()
        for key, val in dic.items():
            if isinstance(val, PathLike):
                dic[key] = str(val)
        return dic

    def _customize_result(self, item: PSObject) -> Any:
        if isinstance(item.BaseObject, PSCustomObject):
            item_proxy = PSCustomObjectProxy(item)
            item_proxy._ps = self
            return item_proxy
        else:
            return item.BaseObject


global ps
ps = PowerShell()
ps.Set_ExecutionPolicy(ExecutionPolicy="Bypass", Scope="Process", Force=True)

public(ps = ps)
