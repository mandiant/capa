# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
import PyInstaller.utils.hooks

# ref: https://groups.google.com/g/pyinstaller/c/amWi0-66uZI/m/miPoKfWjBAAJ
binaries = PyInstaller.utils.hooks.collect_dynamic_libs("capstone")
