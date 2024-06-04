# -*- mode: python -*-
# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
import sys

import wcwidth
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
        # capa.render.default uses tabulate that depends on wcwidth.
        # it seems wcwidth uses a json file `version.json`
        # and this doesn't get picked up by pyinstaller automatically.
        # so we manually embed the wcwidth resources here.
        #
        # ref: https://stackoverflow.com/a/62278462/87207
        (Path(wcwidth.__file__).parent, "wcwidth"),
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
        # tqdm provides renderers for ipython,
        # however, this drags in a lot of dependencies.
        # since we don't spawn a notebook, we can safely remove these.
        "IPython",
        "ipywidgets",
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
        "binaryninja",
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
