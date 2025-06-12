Changelog
=========

0.3.4 (2025-06-11)
------------------
- Little cleanup.
- Setup (dependencies) update.

0.3.3 (2025-05-15)
------------------
- The distribution is now created using 'build' instead of 'setuptools'.
- Setup (dependencies) update (due to regressions in tox and setuptools).

0.3.2 (2025-05-08)
------------------
- Support for PyPy has been removed (due to problems with pythonnet).
- Drop support for Python 3.9 (due to compatibility issues).
- Add 'Host' property.
- Add 'DebugPreference' property.
- | Bugfix: Most outputs of the Write_*() cmdlet's are now visible in the
  | Python console (outputs of the Write_Output() are still not visible).
- Update readthedocs's python to version 3.13
- Update tox's base_python to version 3.13
- Setup (dependencies) update.

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
- Add support for PyPy 3.11
- Drop support for PyPy 3.9
- Setup (dependencies) update.

0.2.3 (2025-02-14)
------------------
- Setup (dependencies) update.

0.2.2 (2025-02-10)
------------------
- Add reference to the System.ServiceProcess
- Copyright year update.

0.2.0 (2025-02-02)
------------------
- Copyright year update.
- Tox configuration is now in native (toml) format.
- Setup (dependencies) update.

0.1.0 (2024-10-30)
------------------
- First release.

0.0.0 (2024-08-13)
------------------
- Initial commit.
