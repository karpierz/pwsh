pwsh
====

Python |package_bold| package provides an API for PowerShell.

Overview
========

TBD...

`PyPI record`_.

`Documentation`_.

Usage
-----

TBD...

Installation
============

Prerequisites:

+ Python 3.10 or higher

  * https://www.python.org/
  * ATTENTION: currently works and is only tested under Windows.

+ pip and setuptools

  * https://pypi.org/project/pip/
  * https://pypi.org/project/setuptools/

To install run:

  .. parsed-literal::

    python -m pip install --upgrade |package|

Development
===========

Prerequisites:

+ Development is strictly based on *tox*. To install it run::

    python -m pip install --upgrade tox

Visit `Development page`_.

Installation from sources:

clone the sources:

  .. parsed-literal::

    git clone |respository| |package|

and run:

  .. parsed-literal::

    python -m pip install ./|package|

or on development mode:

  .. parsed-literal::

    python -m pip install --editable ./|package|

License
=======

  | |copyright|
  | Licensed under the zlib/libpng License
  | https://opensource.org/license/zlib
  | Please refer to the accompanying LICENSE file.

Authors
=======

* Adam Karpierz <adam@karpierz.net>

.. |package| replace:: pwsh
.. |package_bold| replace:: **pwsh**
.. |copyright| replace:: Copyright (c) 2024-2025 Adam Karpierz
.. |respository| replace:: https://github.com/karpierz/pwsh.git
.. _Development page: https://github.com/karpierz/pwsh
.. _PyPI record: https://pypi.org/project/pwsh/
.. _Documentation: https://pw-sh.readthedocs.io/
