# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
import PyInstaller.utils.hooks

binaries = PyInstaller.utils.hooks.collect_dynamic_libs("capstone")