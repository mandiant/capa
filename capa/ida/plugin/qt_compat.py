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

"""
Qt compatibility layer for capa IDA Pro plugin.

Handles PyQt5 (IDA < 9.2) vs PySide6 (IDA >= 9.2) differences.
This module provides a unified import interface for Qt modules and handles
API changes between Qt5 and Qt6.
"""

try:
    # IDA 9.2+ uses PySide6
    from PySide6 import QtGui, QtCore, QtWidgets
    from PySide6.QtGui import QAction

    QT_LIBRARY = "PySide6"
    Signal = QtCore.Signal
except ImportError:
    # Older IDA versions use PyQt5
    try:
        from PyQt5 import QtGui, QtCore, QtWidgets
        from PyQt5.QtWidgets import QAction

        QT_LIBRARY = "PyQt5"
        Signal = QtCore.pyqtSignal
    except ImportError:
        raise ImportError("Neither PySide6 nor PyQt5 is available. Cannot initialize capa IDA plugin.")

Qt = QtCore.Qt


def qt_get_item_flag_tristate():
    """
    Get the tristate item flag compatible with Qt5 and Qt6.

    Qt5 (PyQt5): Uses Qt.ItemIsTristate
    Qt6 (PySide6): Qt.ItemIsTristate was removed, uses Qt.ItemIsAutoTristate

    ItemIsAutoTristate automatically manages tristate based on child checkboxes,
    matching the original ItemIsTristate behavior where parent checkboxes reflect
    the check state of their children.

    Returns:
        int: The appropriate flag value for the Qt version

    Raises:
        AttributeError: If the tristate flag cannot be found in the Qt library
    """
    if QT_LIBRARY == "PySide6":
        # Qt6: ItemIsTristate was removed, replaced with ItemIsAutoTristate
        # Try different possible locations (API varies slightly across PySide6 versions)
        if hasattr(Qt, "ItemIsAutoTristate"):
            return Qt.ItemIsAutoTristate
        elif hasattr(Qt, "ItemFlag") and hasattr(Qt.ItemFlag, "ItemIsAutoTristate"):
            return Qt.ItemFlag.ItemIsAutoTristate
        else:
            raise AttributeError(
                "Cannot find ItemIsAutoTristate in PySide6. "
                + "Your PySide6 version may be incompatible with capa. "
                + f"Available Qt attributes: {[attr for attr in dir(Qt) if 'Item' in attr]}"
            )
    else:
        # Qt5: Use the original ItemIsTristate flag
        return Qt.ItemIsTristate


__all__ = ["qt_get_item_flag_tristate", "Signal", "QAction", "QtGui", "QtCore", "QtWidgets"]
