# -*- mode: python -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

import capa.rules.cache

from pathlib import Path

# SPECPATH is a global variable which points to .spec file path
capa_dir = Path(SPECPATH).parent.parent
rules_dir = capa_dir / 'rules'
cache_dir = capa_dir / 'cache'

if not capa.rules.cache.generate_rule_cache(rules_dir, cache_dir):
    sys.exit(-1)

a = Analysis(
    # when invoking pyinstaller from the project root,
    # this gets invoked from the directory of the spec file,
    # i.e. ./.github/pyinstaller
    ["../../capa/main.py"],
    pathex=["capa"],
    binaries=None,
    datas=[
        # when invoking pyinstaller from the project root,
        # this gets invoked from the directory of the spec file,
        # i.e. ./.github/pyinstaller
        ("../../rules", "rules"),
        ("../../sigs", "sigs"),
        ("../../cache", "cache"),
    ],
    # when invoking pyinstaller from the project root,
    # this gets run from the project root.
    hookspath=[".github/pyinstaller/hooks"],
    runtime_hooks=None,
    excludes=[
        # ignore packages that would otherwise be bundled with the .exe.
        # review: build/pyinstaller/xref-pyinstaller.html
        # we don't do any GUI stuff, so ignore these modules
        "tkinter",
        "_tkinter",
        "Tkinter",
        # these are pulled in by networkx
        # but we don't need to compute the strongly connected components.
        "numpy",
        "scipy",
        "matplotlib",
        "pandas",
        "pytest",
        # deps from viv that we don't use.
        # this duplicates the entries in `hook-vivisect`,
        # but works better this way.
        "vqt",
        "vdb.qt",
        "envi.qt",
        "PyQt5",
        "qt5",
        "pyqtwebengine",
        "pyasn1",
        # don't pull in Binary Ninja/IDA bindings that should
        # only be installed locally.
        "binaryninja",
        "ida",
    ],
)

a.binaries = a.binaries - TOC([("tcl85.dll", None, None), ("tk85.dll", None, None), ("_tkinter", None, None)])

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    exclude_binaries=False,
    name="capa",
    icon="logo.ico",
    debug=False,
    strip=False,
    upx=True,
    console=True,
)

# enable the following to debug the contents of the .exe
#
# coll = COLLECT(exe,
#               a.binaries,
#               a.zipfiles,
#               a.datas,
#               strip=None,
#               upx=True,
#               name='capa-dat')
