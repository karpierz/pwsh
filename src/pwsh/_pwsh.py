# flake8-in-file-ignores: noqa: E402

# Copyright (c) 2012 Adam Karpierz
# SPDX-License-Identifier: Zlib

from typing import TypeAlias, Any, NoReturn
from typing_extensions import Self
from collections.abc import Callable, Sequence, Generator
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

__all__ = ('adict', 'defaultadict', 'Path', 'PSObject', 'PSCustomObject',
           'module_path', 'CmdLet', 'PowerShell', 'ps')


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
        "SystemDrive", "SystemRoot", "WinDir", "ComSpec",
        "TEMP", "TMP", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
        "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
        "ProgramData", "ALLUSERSPROFILE", "PUBLIC", "USERPROFILE", "APPDATA",
        "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "HOME", "OneDrive",
    )}

    def __getitem__(self, key: str) -> Path | str | None:
        """Item access"""
        inst = super().__getitem__("_inst")
        value = inst.Get_Content(Path=rf"env:\{key}", EA="0")
        if not value: return None
        return Path(value[0]) if key.lower() in Env.path_keys else value[0]

    def __setitem__(self, key: str, value: Any) -> None:
        """Item assignment"""
        inst = super().__getitem__("_inst")
        if value is None:
            inst.Set_Content(Path=rf"env:\{key}", Value=value)
        else:
            inst.Set_Content(Path=rf"env:\{key}", Value=value)

    # def __getattr__(self, key: str) -> Path | str | None: ...
    # def __setattr__(self, key: str, value: Any) -> None: ...


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

    def Throw(self, expression: Any | None = None) -> NoReturn:
        if expression is not None:
            self.cmd("Invoke-Expression", Command=f'throw "{expression}"')
            msg = f"{expression}"
        else:
            self.cmd("Invoke-Expression", Command="throw")
            msg = "ScriptHalted"
        raise self.Exception(msg)

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
        return Path(result) if result else None

    @property
    def WindowsSystemPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.System
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def UserProfilePath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.UserProfile
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def DesktopPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.DesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def ProgramsPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.Programs
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def StartMenuPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.StartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def StartupPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.Startup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def LocalApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.LocalApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def ApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.ApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def CommonDesktopPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonDesktopDirectory
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def CommonProgramsPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonPrograms
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def CommonStartMenuPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonStartMenu
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def CommonStartupPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonStartup
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

    @property
    def CommonApplicationDataPath(self) -> Path | None:
        kind = System.Environment.SpecialFolder.CommonApplicationData
        result = System.Environment.GetFolderPath(kind)
        return Path(result) if result else None

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

    # https://learn.microsoft.com/en-us/powershell/scripting/whats-new/
    #         differences-from-windows-powershell?view=powershell-7.5
    #
    # Modules no longer shipped with PowerShell
    #
    # For various compatibility reasons, the following modules are no longer included in
    # PowerShell.
    #
    #  ISE
    #  Microsoft.PowerShell.LocalAccounts
    #  Microsoft.PowerShell.ODataUtils
    #  Microsoft.PowerShell.Operation.Validation
    #  PSScheduledJob
    #  PSWorkflow
    #  PSWorkflowUtility
    #
    # Cmdlets removed from PowerShell
    #
    # For the modules that are included in PowerShell, the following cmdlets were removed
    # from PowerShell for various compatibility reasons or the use of unsupported APIs.
    #
    # CimCmdlets
    #   Export-BinaryMiLog
    #
    # Microsoft.PowerShell.Core
    #
    #     Add-PSSnapin
    #     Get-PSSnapin
    #     Remove-PSSnapin
    #     Export-Console
    #     Resume-Job
    #     Suspend-Job
    #
    # Microsoft.PowerShell.Diagnostics
    #
    #     Export-Counter
    #     Import-Counter
    #
    # Microsoft.PowerShell.Management
    #
    #     Enable-ComputerRestore
    #     Disable-ComputerRestore
    #     Checkpoint-Computer
    #     Add-Computer
    #     Restore-Computer
    #     Remove-Computer
    #     Get-ComputerRestorePoint
    #     Reset-ComputerMachinePassword
    #     Test-ComputerSecureChannel
    #     Clear-EventLog
    #     Get-ControlPanelItem
    #     Get-EventLog
    #     Get-WmiObject
    #     Invoke-WmiMethod
    #     Limit-EventLog
    #     New-EventLog
    #     Write-EventLog
    #     New-WebServiceProxy
    #     Register-WmiEvent
    #     Remove-EventLog
    #     Remove-WmiObject
    #     Set-WmiInstance
    #     Show-ControlPanelItem
    #     Show-EventLog
    #     Start-Transaction
    #     Complete-Transaction
    #     Undo-Transaction
    #     Get-Transaction
    #     Use-Transaction
    #
    # Microsoft.PowerShell.Utility
    #
    #     Convert-String
    #     ConvertFrom-String
    #
    # PSDesiredStateConfiguration
    #
    #     Disable-DscDebug
    #     Enable-DscDebug
    #     Get-DscConfiguration
    #     Get-DscConfigurationStatus
    #     Get-DscLocalConfigurationManager
    #     Publish-DscConfiguration
    #     Remove-DscConfigurationDocument
    #     Restore-DscConfiguration
    #     Set-DscLocalConfigurationManager
    #     Start-DscConfiguration
    #     Stop-DscConfiguration
    #     Test-DscConfiguration
    #     Update-DscConfiguration
    #
    # WMI v1 cmdlets
    #
    # The following WMI v1 cmdlets were removed from PowerShell:
    #
    #     Register-WmiEvent
    #     Set-WmiInstance
    #     Invoke-WmiMethod
    #     Get-WmiObject
    #     Remove-WmiObject
    #
    # The CimCmdlets module (aka WMI v2) cmdlets perform the same function and provide
    # new functionality and a redesigned syntax.
    # New-WebServiceProxy cmdlet removed
    #
    # .NET Core does not support the Windows Communication Framework, which provide
    # services for using the SOAP protocol.
    # This cmdlet was removed because it requires SOAP.
    # *-Transaction cmdlets removed
    #
    # These cmdlets had very limited usage.
    # The decision was made to discontinue support for them.
    #
    #     Complete-Transaction
    #     Get-Transaction
    #     Start-Transaction
    #     Undo-Transaction
    #     Use-Transaction
    #
    # *-EventLog cmdlets
    #
    # Due to the use of unsupported APIs, the *-EventLog cmdlets have been removed
    # from PowerShell.
    # Get-WinEvent and New-WinEvent are available to get and create events on Windows.
    # Cmdlets that use the Windows Presentation Framework (WPF)
    #
    # .NET Core 3.1 added support for WPF, so the release of PowerShell 7.0 restored
    # the following Windows-specific features:
    #
    #     The Show-Command cmdlet
    #     The Out-GridView cmdlet
    #     The ShowWindow parameter of Get-Help
    #
    # PowerShell Desired State Configuration (DSC) changes
    #
    # Invoke-DscResource was restored as an experimental feature in PowerShell 7.0.
    #
    # Beginning with PowerShell 7.2, the PSDesiredStateConfiguration module has been
    # removed from PowerShell and has been published to the PowerShell Gallery.
    # For more information, see the announcement in the PowerShell Team blog.

    # Microsoft.PowerShell.Core

    # Cmdlet                            Description
    # ------                            -----------
    # Enable-PSRemoting                 Configures the computer to receive remote commands.
    # Disable-PSRemoting                Prevents PowerShell endpoints from receiving remote
    #                                   connections.
    # Enable-PSSessionConfiguration     Enables the session configurations on the local computer.
    # Disable-PSSessionConfiguration    Disables session configurations on the local computer.
    # Register-PSSessionConfiguration   Creates and registers a new session configuration.
    # Unregister-PSSessionConfiguration Deletes registered session configurations from the
    #                                   computer.
    # Get-PSSessionConfiguration        Gets the registered session configurations on the
    #                                   computer.
    # Set-PSSessionConfiguration        Changes the properties of a registered session
    #                                   configuration.
    # Get-PSSession                     Gets the PowerShell sessions on local and remote
    #                                   computers.
    # New-PSSession                     Creates a persistent connection to a local or remote
    #                                   computer.
    # Connect-PSSession                 Reconnects to disconnected sessions.
    # Disconnect-PSSession              Disconnects from a session.
    # Enter-PSSession                   Starts an interactive session with a remote computer.
    # Exit-PSSession                    Ends an interactive session with a remote computer.
    # Receive-PSSession                 Gets results of commands in disconnected sessions
    # Remove-PSSession                  Closes one or more PowerShell sessions (PSSessions).
    # Enter-PSHostProcess               Connects to and enters into an interactive session with a
    #                                   local process.
    # Exit-PSHostProcess                Closes an interactive session with a local process.
    # Export-ModuleMember               Specifies the module members that are exported.
    # Get-PSHostProcessInfo             Gets process information about the PowerShell host.
    # Get-PSSessionCapability           Gets the capabilities of a specific user on a constrained
    #                                   session configuration.
    # Get-Verb                          Gets approved PowerShell verbs.
    # New-ModuleManifest                Creates a new module manifest.
    # Test-ModuleManifest               Verifies that a module manifest file accurately describes
    #                                   the contents of a module.
    # New-PSRoleCapabilityFile          Creates a file that defines a set of capabilities to be
    #                                   exposed through a session configuration.
    # New-PSSessionConfigurationFile    Creates a file that defines a session configuration.
    # Test-PSSessionConfigurationFile   Verifies the keys and values in a session configuration
    #                                   file.
    # New-PSSessionOption               Creates an object that contains advanced options for
    #                                   a PSSession.
    # New-PSTransportOption             Creates an object that contains advanced options for
    #                                   a session configuration.
    # Out-Default                       Sends the output to the default formatter and to the
    #                                   default output cmdlet.
    # Out-Host                          Sends output to the command line.
    # Out-Null                          Hides the output instead of sending it down the pipeline
    #                                   or displaying it.
    # Register-ArgumentCompleter        Registers a custom argument completer.
    # Set-PSDebug                       Turns script debugging features on and off, sets the trace
    #                                   level, and toggles strict mode.
    # Set-StrictMode                    Establishes and enforces coding rules in expressions,
    #                                   scripts, and script blocks.
    # TabExpansion2                     A helper function that wraps the CompleteInput() method
    #                                   of the CommandCompletion class to provide tab completion
    #                                   for PowerShell scripts.

    # Import-Module Adds modules to the current session.
    Import_Module = CmdLet("Import-Module")
    # New-Module    Creates a new dynamic module that exists only in memory.
    New_Module    = CmdLet("New-Module")
    # Get-Module    List the modules imported in the current session or that can be imported
    #               from the PSModulePath.
    Get_Module    = CmdLet("Get-Module")
    # Remove-Module Removes modules from the current session.
    Remove_Module = CmdLet("Remove-Module")

    # Get-Command    Gets all commands.
    Get_Command    = CmdLet("Get-Command")
    # Invoke-Command Runs commands on local and remote computers.
    Invoke_Command = CmdLet("Invoke-Command")

    # ForEach-Object  Performs an operation against each item in a collection of input objects.
    _ForEach_Object = CmdLet("ForEach-Object")

    def ForEach_Object(self, InputObject: Any, **kwargs: Any) -> Any:
        return self._ForEach_Object(InputObject=InputObject, **kwargs)

    # Where-Object  Selects objects from a collection based on their property values.
    _Where_Object = CmdLet("Where-Object")

    def Where_Object(self, InputObject: Any, **kwargs: Any) -> Any:
        return self._Where_Object(InputObject=InputObject, **kwargs)

    # Start-Job   Starts a PowerShell background job.
    Start_Job   = CmdLet("Start-Job",   flatten_result=True)
    # Stop-Job    Stops a PowerShell background job.
    Stop_Job    = CmdLet("Stop-Job",    flatten_result=True)
    # Get-Job     Gets PowerShell background jobs that are running in the current session.
    Get_Job     = CmdLet("Get-Job",     flatten_result=True)
    # Wait-Job    Waits until one or all of the PowerShell jobs running in the session are in
    #             a terminating state.
    Wait_Job    = CmdLet("Wait-Job",    flatten_result=True)
    # Receive-Job Gets the results of the PowerShell background jobs in the current session.
    Receive_Job = CmdLet("Receive-Job", flatten_result=True)
    # Remove-Job  Deletes a PowerShell background job.
    Remove_Job  = CmdLet("Remove-Job")
    # Debug-Job   Debugs a running background, remote, or Windows PowerShell Workflow job.
    Debug_Job   = CmdLet("Debug-Job")

    # Clear-Host Clears the display in the host program.
    Clear_Host = CmdLet("Clear-Host")

    # Get-Help    Displays information about PowerShell commands and concepts.
    Get_Help    = CmdLet("Get-Help",    flatten_result=True)
    # Update-Help Downloads and installs the newest help files on your computer.
    Update_Help = CmdLet("Update-Help", flatten_result=True)
    # Save-Help   Downloads and saves the newest help files to a file system directory.
    Save_Help   = CmdLet("Save-Help",   flatten_result=True)

    # Get-History    Gets a list of the commands entered during the current session.
    Get_History    = CmdLet("Get-History")
    # Clear-History  Deletes entries from the PowerShell session command history.
    Clear_History  = CmdLet("Clear-History", flatten_result=True)
    # Add-History    Appends entries to the session history.
    Add_History    = CmdLet("Add-History")
    # Invoke-History Runs commands from the session history.
    Invoke_History = CmdLet("Invoke-History")

    # Microsoft.PowerShell.Management

    # Cmdlet                         Description
    # ------                         -----------
    # Rename-Computer   Renames a computer.
    # Restart-Computer  Restarts the operating system on local and remote computers.
    # Stop-Computer     Stops (shuts down) local and remote computers.
    # Get-ComputerInfo  Gets a consolidated object of system and operating system properties.
    # Get-HotFix        Gets the hotfixes that are installed on local or remote computers.
    # Get-PSProvider    Gets information about the specified PowerShell provider.
    # Invoke-Item       Performs the default action on the specified item.
    # Join-Path         Combines a path and a child path into a single path.
    # Split-Path        Returns the specified part of a path.
    # Get-Clipboard     Gets the current Windows clipboard entry.
    # Set-Clipboard     Sets the current Windows clipboard entry.
    # Get-TimeZone      Gets the current time zone or a list of available time zones.
    # Set-TimeZone      Sets the system time zone to a specified time zone.
    # Test-Connection   Sends ICMP echo request packets, or pings, to one or more computers.

    # https://learn.microsoft.com/en-us/powershell/scripting/how-to-use-docs?view=powershell-5.1
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/
    #         about_providers?view=powershell-5.1

    # Push-Location Adds the current location to the top of a location stack.
    Push_Location = CmdLet("Push-Location")
    # Pop-Location  Changes the current location to the location most recently pushed onto
    #               the stack.
    Pop_Location  = CmdLet("Pop-Location")
    # Get-Location  Gets information about the current working location or a location stack.
    Get_Location  = CmdLet("Get-Location")
    # Set-Location  Sets the current working location to a specified location.
    Set_Location  = CmdLet("Set-Location")

    # Get-ChildItem Gets the items and child items in one or more specified locations.
    Get_ChildItem = CmdLet("Get-ChildItem",
                           customize_result = lambda self, result: result or [])

    # Get-Item    Gets the item at the specified location.
    Get_Item    = CmdLet("Get-Item")
    # New-Item    Creates a new item.
    New_Item    = CmdLet("New-Item")
    # Set-Item    Changes the value of an item to the value specified in the command.
    Set_Item    = CmdLet("Set-Item")
    # Copy-Item   Copies an item from one location to another.
    Copy_Item   = CmdLet("Copy-Item")
    # Move-Item   Moves an item from one location to another.
    Move_Item   = CmdLet("Move-Item")
    # Remove-Item Deletes the specified items.
    Remove_Item = CmdLet("Remove-Item")
    # Rename-Item Renames an item in a PowerShell provider namespace.
    Rename_Item = CmdLet("Rename-Item")
    # Clear-Item  Clears the contents of an item, but does not delete the item.
    Clear_Item  = CmdLet("Clear-Item")

    # Get-ItemProperty    Gets the properties of a specified item.
    Get_ItemProperty    = CmdLet("Get-ItemProperty")
    # New-ItemProperty    Creates a new property for an item and sets its value.
    New_ItemProperty    = CmdLet("New-ItemProperty")
    # Set-ItemProperty    Creates or changes the value of a property of an item.
    Set_ItemProperty    = CmdLet("Set-ItemProperty")
    # Copy-ItemProperty   Copies a property and value from a specified location to another
    #                     location.
    Copy_ItemProperty   = CmdLet("Copy-ItemProperty")
    # Move-ItemProperty   Moves a property from one location to another.
    Move_ItemProperty   = CmdLet("Move-ItemProperty")
    # Remove-ItemProperty Deletes the property and its value from an item.
    Remove_ItemProperty = CmdLet("Remove-ItemProperty", flatten_result=True)
    # Rename-ItemProperty Renames a property of an item.
    Rename_ItemProperty = CmdLet("Rename-ItemProperty", flatten_result=True)
    # Clear-ItemProperty  Clears the value of a property but does not delete the property.
    Clear_ItemProperty  = CmdLet("Clear-ItemProperty",  flatten_result=True)

    # Get-ItemPropertyValue  Gets the value for one or more properties of a specified item.
    _Get_ItemPropertyValue = CmdLet("Get-ItemPropertyValue")

    def Get_ItemPropertyValue(self, **kwargs: Any) -> Sequence[Any]:
        return (self._Get_ItemPropertyValue(**kwargs)
                if self.Get_ItemProperty(**kwargs) else [])

    # Test-Path    Determines whether all elements of a path exist.
    Test_Path    = CmdLet("Test-Path",
                          customize_result = lambda self, result: bool(result[0]))
    # Resolve-Path Resolves the wildcard characters in a path, and displays the path contents.
    Resolve_Path = CmdLet("Resolve-Path")
    # Convert-Path Converts a path from a PowerShell path to a PowerShell provider path.
    Convert_Path = CmdLet("Convert-Path")

    # Get-Content   Gets the content of the item at the specified location.
    Get_Content   = CmdLet("Get-Content")
    # Set-Content   Writes new content or replaces existing content in a file.
    Set_Content   = CmdLet("Set-Content")
    # Add-Content   Adds content to the specified items, such as adding words to a file.
    Add_Content   = CmdLet("Add-Content")
    # Clear-Content Deletes the contents of an item, but does not delete the item.
    Clear_Content = CmdLet("Clear-Content")

    # Get-Process  Gets the processes that are running on the local computer or a remote
    #              computer.
    Get_Process  = CmdLet("Get-Process")
    # Wait-Process Waits for the processes to be stopped before accepting more input.
    Wait_Process = CmdLet("Wait-Process")

    # Start-Process  Starts one or more processes on the local computer.
    _Start_Process = CmdLet("Start-Process")

    def Start_Process(self, **kwargs: Any) -> Any:
        kwargs = kwargs.copy()
        if "ArgumentList" in kwargs:
            kwargs["ArgumentList"] = Array[String](kwargs["ArgumentList"])
        return self._Start_Process(**kwargs)

    # Stop-Process  Stops one or more running processes.
    _Stop_Process = CmdLet("Stop-Process")

    def Stop_Process(self, **kwargs: Any) -> Any:
        Force = kwargs.pop("Force", True)
        return self._Stop_Process(Force=Force, **kwargs)

    # Debug-Process Debugs one or more processes running on the local computer.
    Debug_Process = CmdLet("Debug-Process")

    # New-Service     Creates a new Windows service.
    New_Service     = CmdLet("New-Service", flatten_result=True)
    # Get-Service     Gets the services on a local or remote computer.
    Get_Service     = CmdLet("Get-Service")
    # Start-Service   Starts one or more stopped services.
    Start_Service   = CmdLet("Start-Service", flatten_result=True)
    # Restart-Service Stops and then starts one or more services.
    Restart_Service = CmdLet("Restart-Service", flatten_result=True)
    # Suspend-Service Suspends (pauses) one or more running services.
    Suspend_Service = CmdLet("Suspend-Service", flatten_result=True)
    # Resume-Service  Resumes one or more suspended (paused) services.
    Resume_Service  = CmdLet("Resume-Service", flatten_result=True)
    # Set-Service     Starts, stops, and suspends a service, and changes its properties.
    Set_Service     = CmdLet("Set-Service", flatten_result=True)
    # Stop-Service    Stops one or more running services.
    Stop_Service    = CmdLet("Stop-Service")

    # Get-PSDrive    Gets drives in the current session.
    Get_PSDrive    = CmdLet("Get-PSDrive")
    # New-PSDrive    Creates temporary and persistent drives that are associated with a location
    #                in an item data store.
    New_PSDrive    = CmdLet("New-PSDrive", flatten_result=True)
    # Remove-PSDrive Deletes temporary PowerShell drives and disconnects mapped network drives.
    Remove_PSDrive = CmdLet("Remove-PSDrive", flatten_result=True)

    # Microsoft.PowerShell.Utility

    # Cmdlet                    Description
    # ------                    -----------
    # ConvertFrom-SddlString    Converts a SDDL string to a custom object.
    # ConvertFrom-StringData    Converts a string containing one or more key and value pairs to a
    #                           hash table.
    # Enable-RunspaceDebug      Enables debugging on runspaces where any breakpoint is preserved
    #                           until a debugger is attached.
    # Disable-RunspaceDebug     Disables debugging on one or more runspaces, and releases any
    #                           pending debugger stop.
    # Get-RunspaceDebug         Shows runspace debugging options.
    # Get-Runspace              Gets active runspaces within a PowerShell host process.
    # Debug-Runspace            Starts an interactive debugging session with a runspace.
    # Enable-PSBreakpoint       Enables the breakpoints in the current console.
    # Disable-PSBreakpoint      Disables the breakpoints in the current console.
    # Get-PSBreakpoint          Gets the breakpoints that are set in the current session.
    # Set-PSBreakpoint          Sets a breakpoint on a line, command, or variable.
    # Remove-PSBreakpoint       Deletes breakpoints from the current console.
    # Export-Alias              Exports information about currently defined aliases to a file.
    # Export-FormatData         Saves formatting data from the current session in a formatting
    #                           file.
    # Export-PSSession          Exports commands from another session and saves them in a
    #                           PowerShell module.
    # Get-Alias                 Gets the aliases for the current session.
    # Get-Culture               Gets the current culture set in the operating system.
    # Get-FormatData            Gets the formatting data in the current session.
    # Get-PSCallStack           Displays the current call stack.
    # Get-TraceSource           Gets PowerShell components that are instrumented for tracing.
    # Get-TypeData              Gets the extended type data in the current session.
    # Get-Random                Gets a random number, or selects objects randomly from a
    #                           collection.
    # Get-Unique                Returns unique items from a sorted list.
    # Import-Alias              Imports an alias list from a file.
    # Import-LocalizedData      Imports language-specific data into scripts and functions based
    #                           on the UI culture that's selected for the operating system.
    # Import-PowerShellDataFile Imports values from a .psd1 file without invoking its contents.
    # Import-PSSession          Imports commands from another session into the current session.
    # Measure-Command           Measures the time it takes to run script blocks and cmdlets.
    # New-Alias                 Creates a new alias.
    # New-Guid                  Creates a GUID.
    # New-TemporaryFile         Creates a temporary file.
    # New-TimeSpan              Creates a TimeSpan object.
    # Out-File                  Sends output to a file.
    # Out-GridView              Sends output to an interactive table in a separate window.
    # Out-Printer               Sends output to a printer.
    # Out-String                Outputs input objects as a string.
    # Get-EventSubscriber       Gets the event subscribers in the current session.
    # Register-EngineEvent      Subscribes to events that are generated by the PowerShell engine
    #                           and by the New-Event cmdlet.
    # Register-ObjectEvent      Subscribes to the events that are generated by a Microsoft
    #                           .NET Framework object.
    # Unregister-Event          Cancels an event subscription.
    # New-Event                 Creates a new event.
    # Get-Event                 Gets the events in the event queue.
    # Wait-Event                Waits until a particular event is raised before continuing to run.
    # Remove-Event              Deletes events from the event queue.
    # Remove-TypeData           Deletes extended types from the current session.
    # Send-MailMessage          Sends an email message.
    # Set-TraceSource           Configures, starts, and stops a trace of PowerShell components.
    # Show-Command              Displays PowerShell command information in a graphical window.
    # Tee-Object                Saves command output in a file or variable and also sends it down
    #                           the pipeline.
    # Trace-Command             Configures and starts a trace of the specified expression or
    #                           command.
    # Unblock-File              Unblocks files that were downloaded from the internet.
    # Update-FormatData         Updates the formatting data in the current session.
    # Update-List               Adds items to and removes items from a property value that
    #                           contains a collection of objects.
    # Update-TypeData           Updates the extended type data in the session.
    # Wait-Debugger             Stops a script in the debugger before running the next statement
    #                           in the script.

    Get_Verb = CmdLet("Get-Verb")
    # Get-Verb [[-verb] <String[]>]

    # Get-UICulture Gets the current UI culture settings in the operating system.
    Get_UICulture = CmdLet("Get-UICulture", flatten_result=True)

    Get_Error = CmdLet("Get-Error")

    # Get-Host Gets an object that represents the current host program.
    Get_Host = CmdLet("Get-Host", flatten_result=True)

    # Get-Date Gets the current date and time.
    Get_Date = CmdLet("Get-Date")
    # Set-Date Changes the system time on the computer to a time that you specify.
    Set_Date = CmdLet("Set-Date")

    # Get-FileHash Computes the hash value for a file by using a specified hash algorithm.
    Get_FileHash = CmdLet("Get-FileHash")

    # New-Variable    Creates a new variable.
    New_Variable    = CmdLet("New-Variable")
    # Get-Variable    Gets the variables in the current console.
    Get_Variable    = CmdLet("Get-Variable")
    # Set-Variable    Sets the value of a variable. Creates the variable if one with the
    #                 requested name does not exist.
    Set_Variable    = CmdLet("Set-Variable")
    # Clear-Variable  Deletes the value of a variable.
    Clear_Variable  = CmdLet("Clear-Variable")
    # Remove-Variable Deletes a variable and its value.
    Remove_Variable = CmdLet("Remove-Variable")

    # Invoke-Expression Runs commands or expressions on the local computer.
    # Invoke-Expression [-Command] <String> [<CommonParameters>]
    Invoke_Expression = CmdLet("Invoke-Expression")

    # Add-Type Adds a Microsoft .NET class to a PowerShell session.
    Add_Type = CmdLet("Add-Type")

    # New-Object     Creates an instance of a Microsoft .NET Framework or COM object.
    New_Object     = CmdLet("New-Object")
    # Select-Object  Selects objects or object properties.
    Select_Object  = CmdLet("Select-Object")
    # Sort-Object    Sorts objects by property values.
    Sort_Object    = CmdLet("Sort-Object")
    # Group-Object   Groups objects that contain the same value for specified properties.
    Group_Object   = CmdLet("Group-Object")
    # Compare-Object Compares two sets of objects.
    Compare_Object = CmdLet("Compare-Object")
    # Get-Member     Gets the properties and methods of objects.
    Get_Member     = CmdLet("Get-Member")
    # Add-Member     Adds custom properties and methods to an instance of a PowerShell object.
    Add_Member     = CmdLet("Add-Member")

    # Set-Alias Creates or changes an alias for a cmdlet or other command in the current
    #           PowerShell session.
    Set_Alias = CmdLet("Set-Alias")

    # Select-String Finds text in strings and files.
    Select_String = CmdLet("Select-String")  # , flatten_result=True)
    # Select-Xml    Finds text in an XML string or document.
    Select_Xml    = CmdLet("Select-Xml")  # , flatten_result=True)

    # Format-Hex    Displays a file or other input as hexadecimal.
    Format_Hex    = CmdLet("Format-Hex")
    # Format-List   Formats the output as a list of properties in which each property appears
    #               on a new line.
    Format_List   = CmdLet("Format-List")
    # Format-Table  Formats the output as a table.
    Format_Table  = CmdLet("Format-Table")
    # Format-Wide   Formats objects as a wide table that displays only one property of each
    #               object.
    Format_Wide   = CmdLet("Format-Wide")
    # Format-Custom Uses a customized view to format the output.
    Format_Custom = CmdLet("Format-Custom")

    # ConvertTo-Csv   Converts .NET objects into a series of character-separated value (CSV)
    #                 strings.
    ConvertTo_Csv   = CmdLet("ConvertTo-Csv")
    # ConvertFrom-Csv Converts object properties in character-separated value (CSV) format into
    #                 CSV versions of the original objects.
    ConvertFrom_Csv = CmdLet("ConvertFrom-Csv")
    # Export-Csv      Converts objects into a series of character-separated value (CSV) strings
    #                 and saves the strings to a file.
    Export_Csv      = CmdLet("Export-Csv")
    # Import-Csv      Creates table-like custom objects from the items in a character-separated
    #                 value (CSV) file.
    Import_Csv      = CmdLet("Import-Csv")

    Test_Json = CmdLet("Test-Json",
                       customize_result = lambda self, result: bool(result[0]))
    # ConvertTo-Json   Converts an object to a JSON-formatted string.
    ConvertTo_Json   = CmdLet("ConvertTo-Json")
    # ConvertFrom-Json Converts a JSON-formatted string to a custom object.
    ConvertFrom_Json = CmdLet("ConvertFrom-Json", flatten_result=True)

    # ConvertTo-Xml Creates an XML-based representation of an object.
    ConvertTo_Xml = CmdLet("ConvertTo-Xml")
    # Export-Clixml Creates an XML-based representation of an object or objects and stores it
    #               in a file.
    Export_Clixml = CmdLet("Export-Clixml")
    # Import-Clixml Imports a CLIXML file and creates corresponding objects in PowerShell.
    Import_Clixml = CmdLet("Import-Clixml")

    # ConvertTo-Html Converts .NET objects into HTML that can be displayed in a Web browser.
    ConvertTo_Html = CmdLet("ConvertTo-Html")

    # Measure-Object Calculates the numeric properties of objects, and the characters, words,
    #                and lines in string objects, such as files of text.
    Measure_Object = CmdLet("Measure-Object")

    # Invoke-WebRequest Gets content from a web page on the internet.
    Invoke_WebRequest = CmdLet("Invoke-WebRequest", flatten_result=True)
    # Invoke-RestMethod Sends an HTTP or HTTPS request to a RESTful web service.
    Invoke_RestMethod = CmdLet("Invoke-RestMethod", flatten_result=True)

    # Start-Sleep Suspends the activity in a script or session for the specified period of time.
    Start_Sleep = CmdLet("Start-Sleep")

    # Clear-RecycleBin Clears the contents of the current user's recycle bin.
    Clear_RecycleBin = CmdLet("Clear-RecycleBin")

    # Write-Host  Writes customized output to a host.
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

    # Write-Information  Specifies how PowerShell handles information stream data for a command.
    _Write_Information = CmdLet("Write-Information", flatten_result=True)

    def Write_Information(self, Msg: Any, **kwargs: Any) -> Any:
        preference = self._customize_ActionPreference(kwargs.get("InformationAction",
                                                                 self.InformationPreference))
        with self.Information(preference):
            return self._Write_Information(Msg=Msg, **kwargs)

    # Write-Warning  Writes a warning message.
    _Write_Warning = CmdLet("Write-Warning", flatten_result=True)

    def Write_Warning(self, Msg: Any, **kwargs: Any) -> Any:
        preference = self._customize_ActionPreference(kwargs.get("WarningAction",
                                                                 self.WarningPreference))
        with self.Warning(preference):
            return self._Write_Warning(Msg=Msg, **kwargs)

    # Write-Error  Writes an object to the error stream.
    _Write_Error = CmdLet("Write-Error", flatten_result=True)

    def Write_Error(self, Msg: Any, **kwargs: Any) -> Any:
        return self._Write_Error(Msg=Msg, **kwargs)

    # Write-Verbose  Writes text to the verbose message stream.
    _Write_Verbose = CmdLet("Write-Verbose", flatten_result=True)

    def Write_Verbose(self, Msg: Any, **kwargs: Any) -> Any:
        preference = (self.VerbosePreference if "Verbose" not in kwargs else
                      Automation.ActionPreference.Continue if kwargs["Verbose"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Verbose(preference):
            return self._Write_Verbose(Msg=Msg, **kwargs)

    # Write-Debug  Writes a debug message to the console.
    _Write_Debug = CmdLet("Write-Debug", flatten_result=True)

    def Write_Debug(self, Msg: Any, **kwargs: Any) -> Any:
        preference = (self.DebugPreference if "Debug" not in kwargs else
                      Automation.ActionPreference.Inquire if kwargs["Debug"] else
                      Automation.ActionPreference.SilentlyContinue)
        with self.Debug(preference):
            return self._Write_Debug(Msg=Msg, **kwargs)

    # Write-Progress  Displays a progress bar within a PowerShell command window.
    _Write_Progress = CmdLet("Write-Progress", flatten_result=True)

    def Write_Progress(self, Activity: Any, **kwargs: Any) -> Any:
        preference = self.ProgressPreference
        with self.Progress(preference):
            return self._Write_Progress(Activity=Activity, **kwargs)

    # Write-Output  Writes the specified objects to the pipeline.
    _Write_Output = CmdLet("Write-Output", flatten_result=True)

    def Write_Output(self, InputObject: Any, **kwargs: Any) -> Any:
        return self._Write_Output(InputObject=InputObject, **kwargs)

    # Read-Host  Reads a line of input from the console.
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

    # Cmdlet              Description
    # ------              -----------
    # Get-ExecutionPolicy Gets the execution policies for the current session.
    Get_ExecutionPolicy = CmdLet("Get-ExecutionPolicy")
    # Set-ExecutionPolicy Sets the PowerShell execution policies for Windows computers.
    Set_ExecutionPolicy = CmdLet("Set-ExecutionPolicy")

    # Get-Credential Gets a credential object based on a user name and password.
    Get_Credential = CmdLet("Get-Credential")

    # Get-Acl Gets the security descriptor for a resource, such as a file or registry key.
    Get_Acl = CmdLet("Get-Acl")
    # Set-Acl Changes the security descriptor of a specified item, such as a file or a
    #         registry key.
    Set_Acl = CmdLet("Set-Acl")

    # Get-CmsMessage       Gets content that has been encrypted by using the Cryptographic
    #                      Message Syntax format.
    Get_CmsMessage       = CmdLet("Get-CmsMessage")
    # Protect-CmsMessage   Encrypts content by using the Cryptographic Message Syntax format.
    Protect_CmsMessage   = CmdLet("Protect-CmsMessage")
    # Unprotect-CmsMessage Decrypts content that has been encrypted by using the Cryptographic
    #                      Message Syntax format.
    Unprotect_CmsMessage = CmdLet("Unprotect-CmsMessage")

    # ConvertTo-SecureString   Converts plain text or encrypted strings to secure strings.
    ConvertTo_SecureString   = CmdLet("ConvertTo-SecureString")
    # ConvertFrom-SecureString Converts a secure string to an encrypted standard string.
    ConvertFrom_SecureString = CmdLet("ConvertFrom-SecureString")

    # Get-PfxCertificate Gets information about PFX certificate files on the computer.
    Get_PfxCertificate = CmdLet("Get-PfxCertificate")

    # Get-AuthenticodeSignature Gets information about the Authenticode signature for a file.
    Get_AuthenticodeSignature = CmdLet("Get-AuthenticodeSignature")
    # Set-AuthenticodeSignature Adds an Authenticode signature to a PowerShell script or other
    #                           file.
    Set_AuthenticodeSignature = CmdLet("Set-AuthenticodeSignature")

    # New-FileCatalog  Creates a Windows catalog file containing cryptographic hashes for files
    #                  and folders in the specified paths.
    New_FileCatalog  = CmdLet("New-FileCatalog")
    # Test-FileCatalog Test-FileCatalog validates whether the hashes contained in a catalog file
    #                  (.cat) matches the hashes of the actual files in order to validate their
    #                  authenticity. This cmdlet is only supported on Windows.
    Test_FileCatalog = CmdLet("Test-FileCatalog")

    # Microsoft.PowerShell.Host

    # Cmdlet           Description
    # ------           -----------
    # Start-Transcript Creates a record of all or part of a PowerShell session to a text file.
    Start_Transcript = CmdLet("Start-Transcript")
    # Stop-Transcript  Stops a transcript.
    Stop_Transcript  = CmdLet("Stop-Transcript")

    # Microsoft.PowerShell.Archive

    # Cmdlet           Description
    # ------           -----------
    # Compress-Archive Creates a compressed archive, or zipped file, from specified files
    #                  and directories.
    Compress_Archive = CmdLet("Compress-Archive")
    # Expand-Archive   Extracts files from a specified archive (zipped) file.
    Expand_Archive   = CmdLet("Expand-Archive")

    # Microsoft.PowerShell.Diagnostics

    # Cmdlet       Description
    # ------       -----------
    # Get-Counter  Gets performance counter data from local and remote computers.
    Get_Counter  = CmdLet("Get-Counter")
    # Get-WinEvent Gets events from event logs and event tracing log files on local and
    #              remote computers.
    Get_WinEvent = CmdLet("Get-WinEvent")
    # New-WinEvent Creates a new Windows event for the specified event provider.
    New_WinEvent = CmdLet("New-WinEvent")

    # Module: ThreadJob

    Start_ThreadJob = CmdLet("Start-ThreadJob")

    # Module: DISM

    # Get-WindowsEdition             Gets edition information about a Windows image.
    Get_WindowsEdition             = CmdLet("Get-WindowsEdition",
                                            flatten_result=True)
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

    # Cmdlet                      Description
    # ------                      -----------
    # Get-CimClass                Gets a list of CIM classes in a specific namespace.
    # Import-BinaryMiLog          Used to re-create the saved objects based on the contents of
    #                             an export file.
    # Get-CimAssociatedInstance   Retrieves the CIM instances that are connected to a specific
    #                             CIM instance by an association.
    # Register-CimIndicationEvent Subscribes to indications using a filter expression or a query
    #                             expression.
    # New-CimSessionOption        Specifies advanced options for the New-CimSession cmdlet.
    # Get-CimSession              Gets the CIM session objects from the current session.
    # New-CimSession              Creates a CIM session.
    # Remove-CimSession           Removes one or more CIM sessions.

    # New-CimInstance    Creates a CIM instance.
    New_CimInstance    = CmdLet("New-CimInstance")
    # Get-CimInstance    Gets the CIM instances of a class from a CIM server.
    Get_CimInstance    = CmdLet("Get-CimInstance")
    # Set-CimInstance    Modifies a CIM instance on a CIM server by calling the ModifyInstance
    #                    method of the CIM class.
    Set_CimInstance    = CmdLet("Set-CimInstance")
    # Remove-CimInstance Removes a CIM instance from a computer.
    Remove_CimInstance = CmdLet("Remove-CimInstance")
    # Invoke-CimMethod   Invokes a method of a CIM class.
    Invoke_CimMethod   = CmdLet("Invoke-CimMethod")

    # Module: ScheduledTasks

    # Cmdlet                             Description
    # ------                             -----------
    # Enable-ScheduledTask              Enables a scheduled task.
    # Disable-ScheduledTask             Disables a scheduled task.
    # Register-ScheduledTask            Registers a scheduled task definition on a local computer.
    # Unregister-ScheduledTask          Unregisters a scheduled task.
    # Export-ScheduledTask              Exports a scheduled task as an XML string.
    # Get-ScheduledTask                 Gets the task definition object of a scheduled task
    #                                   that is registered on the local computer.
    # Get-ScheduledTaskInfo             Gets run-time information for a scheduled task.
    # New-ScheduledTask                 Creates a scheduled task instance.
    # New-ScheduledTaskAction           Creates a scheduled task action.
    # New-ScheduledTaskPrincipal        Creates an object that contains a scheduled task principal.
    # New-ScheduledTaskSettingsSet      Creates a new scheduled task settings object.
    # New-ScheduledTaskTrigger          Creates a scheduled task trigger object.
    # Set-ScheduledTask                 Modifies a scheduled task.
    # Start-ScheduledTask               Starts one or more instances of a scheduled task.
    # Stop-ScheduledTask                Stops all running instances of a task.
    # Register-ClusteredScheduledTask   Registers a scheduled task on a failover cluster.
    # Unregister-ClusteredScheduledTask Removes a scheduled task from a failover cluster.
    # Get-ClusteredScheduledTask        Gets clustered scheduled tasks for a failover cluster.
    # Set-ClusteredScheduledTask        Changes settings for a clustered scheduled task.

    # Module: Wdac

    # Cmdlet                   Description
    # ------                   -----------
    # Enable-OdbcPerfCounter   Enables connection pooling Performance Monitor counters.
    # Disable-OdbcPerfCounter  Disables connection pooling Performance Monitor counters.
    # Get-OdbcPerfCounter      Gets connection pooling Performance Monitor counters.
    # Enable-WdacBidTrace      Enables BidTrace for troubleshooting Windows DAC.
    # Disable-WdacBidTrace     Disables BidTrace for Windows DAC.
    # Get-WdacBidTrace         Gets BidTrace settings.
    # Get-OdbcDriver           Gets installed ODBC drivers.
    # Set-OdbcDriver           Configures the properties for installed ODBC drivers.
    # Get-OdbcDsn              Gets ODBC DSNs.
    # Add-OdbcDsn              Adds an ODBC DSN.
    # Set-OdbcDsn              Configures properties for existing ODBC DSNs.
    # Remove-OdbcDsn           Removes ODBC DSNs.

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
