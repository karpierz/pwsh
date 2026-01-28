Changelog
=========

0.5.3 (2026-01-27)
------------------
- Added CmdLets:

  + Module: Microsoft.PowerShell.Core
  +   Wait_Job, Receive_Job, Remove_Job, Debug_Job,
  +   Get_History, Clear_History, Add_History, Invoke_History,
  + Module: Microsoft.PowerShell.Management
  +   Get_Location, Set_Location,
  +   Wait_Process, Debug_Process,
  +   Restart_Service, Suspend_Service, Resume_Service, Set_Service,
  + Module: Microsoft.PowerShell.Utility
  +   Sort_Object, Group_Object, Compare_Object, Select_Xml
  + Module: DISM
  +   Get_WindowsEdition

- Updated CmdLets:

  + Module: Microsoft.PowerShell.Management
  +   Stop_Process  - -Force is now default.
  +   Get_WmiObject - obsoleted, removed due to incompatibility with v.6.0+

- Added support for Python 3.14
- BugFixes for PowerShell.*Path propetries.
- Expanding the set of known environment variables that represent paths.
- Improved type checking.
- Prepared and marked the package as typed.
- Switched from tox to Nox for project automation.
- The documentation has been moved from Read the Docs to GitHub Pages.
- Setup update (mainly dependencies) and bug fixes.

0.4.0 (2025-11-30)
------------------
- 100% code linting.
- Add Resolve_Path().
- Utils come from py-utlx.
- Copyright year update.
- Added the 'tool.tox.env.cleanup' test environment.
- Setup update (mainly dependencies).

0.3.6 (2025-08-28)
------------------
- | Import of internal PowerShell assemblies has been improved and is
  | now more portable between different versions of PowerShell.
  | From now on, assemblies are first imported from own PowerShell set.
- Making the package typed (but should be enhanced and more restricted).
- General improvements and cleanup.
- Setup update (mainly dependencies).

0.3.4 (2025-06-11)
------------------
- Little cleanup.
- Setup update (mainly dependencies).

0.3.3 (2025-05-15)
------------------
- The distribution is now built using 'build' instead of 'setuptools'.
- Setup update (mainly dependencies) (due to regressions in tox and setuptools).

0.3.2 (2025-05-08)
------------------
- Support for PyPy has been removed (due to problems with pythonnet).
- Dropped support for Python 3.9 (due to compatibility issues).
- Add 'Host' property.
- Add 'DebugPreference' property.
- | Bugfix: Most outputs of the Write_*() cmdlet's are now visible in the
  | Python console (outputs of the Write_Output() are still not visible).
- Updated Read the Docs' Python version to 3.13
- Updated tox's base_python to version 3.13
- Setup update (mainly dependencies).

0.2.11 (2025-04-24)
-------------------
- Fix for Stop_Process. -Force is now the default.
- Change base_python to Python 3.13

0.2.9 (2025-04-10)
------------------
- Fix compability for Python >= 3.13

0.2.8 (2025-03-30)
------------------
- Add New_Service().

0.2.6 (2025-03-25)
------------------
- Add LocalApplicationDataPath property.

0.2.5 (2025-03-20)
------------------
- Added support for PyPy 3.11
- Dropped support for PyPy 3.9
- Setup update (mainly dependencies).

0.2.3 (2025-02-14)
------------------
- Setup update (mainly dependencies).

0.2.2 (2025-02-10)
------------------
- Add reference to the System.ServiceProcess
- Copyright year update.

0.2.0 (2025-02-02)
------------------
- Copyright year update.
- Tox configuration is now in native (toml) format.
- Setup update (mainly dependencies).

0.1.0 (2024-10-30)
------------------
- First release.

0.0.0 (2024-08-13)
------------------
- Initial commit.
