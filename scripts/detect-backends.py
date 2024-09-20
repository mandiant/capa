# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import sys
import logging
import importlib.util
from typing import Optional
from pathlib import Path

import rich
import rich.table

from capa.features.extractors.ida.idalib import find_idalib, load_idalib, is_idalib_installed

logger = logging.getLogger(__name__)


def get_desktop_entry(name: str) -> Optional[Path]:
    """
    Find the path for the given XDG Desktop Entry name.

    Like:

        >> get_desktop_entry("com.vector35.binaryninja.desktop")
        Path("~/.local/share/applications/com.vector35.binaryninja.desktop")
    """
    assert sys.platform in ("linux", "linux2")
    assert name.endswith(".desktop")

    default_data_dirs = f"/usr/share/applications:{Path.home()}/.local/share"
    data_dirs = os.environ.get("XDG_DATA_DIRS", default_data_dirs)
    for data_dir in data_dirs.split(":"):
        applications = Path(data_dir) / "applications"
        for application in applications.glob("*.desktop"):
            if application.name == name:
                return application

    return None


def get_binaryninja_path(desktop_entry: Path) -> Optional[Path]:
    # from: Exec=/home/wballenthin/software/binaryninja/binaryninja %u
    # to:        /home/wballenthin/software/binaryninja/
    for line in desktop_entry.read_text(encoding="utf-8").splitlines():
        if not line.startswith("Exec="):
            continue

        if not line.endswith("binaryninja %u"):
            continue

        binaryninja_path = Path(line[len("Exec=") : -len("binaryninja %u")])
        if not binaryninja_path.exists():
            return None

        return binaryninja_path

    return None


def find_binaryninja() -> Optional[Path]:
    if sys.platform == "linux" or sys.platform == "linux2":
        # ok
        logger.debug("detected OS: linux")
    elif sys.platform == "darwin":
        raise NotImplementedError(f"unsupported platform: {sys.platform}")
    elif sys.platform == "win32":
        raise NotImplementedError(f"unsupported platform: {sys.platform}")
    else:
        raise NotImplementedError(f"unsupported platform: {sys.platform}")

    desktop_entry = get_desktop_entry("com.vector35.binaryninja.desktop")
    if not desktop_entry:
        return None
    logger.debug("found Binary Ninja application: %s", desktop_entry)

    binaryninja_path = get_binaryninja_path(desktop_entry)
    if not binaryninja_path:
        return None
    logger.debug("found Binary Ninja installation: %s", binaryninja_path)

    module_path = binaryninja_path / "python"
    if not module_path.exists():
        return None

    if not (module_path / "binaryninja" / "__init__.py").exists():
        return None

    return module_path


def is_binaryninja_installed() -> bool:
    """Is the binaryninja module ready to import?"""
    try:
        return importlib.util.find_spec("binaryninja") is not None
    except ModuleNotFoundError:
        return False


def has_binaryninja() -> bool:
    if is_binaryninja_installed():
        logger.debug("found installed Binary Ninja API")
        return True

    logger.debug("Binary Ninja API not installed, searching...")

    binaryninja_path = find_binaryninja()
    if not binaryninja_path:
        logger.debug("failed to find Binary Ninja installation")

    logger.debug("found Binary Ninja API: %s", binaryninja_path)
    return binaryninja_path is not None


def load_binaryninja() -> bool:
    try:
        import binaryninja

        return True
    except ImportError:
        binaryninja_path = find_binaryninja()
        if not binaryninja_path:
            return False

        sys.path.append(binaryninja_path.absolute().as_posix())
        try:
            import binaryninja  # noqa: F401 unused import

            return True
        except ImportError:
            return False


def is_vivisect_installed() -> bool:
    try:
        return importlib.util.find_spec("vivisect") is not None
    except ModuleNotFoundError:
        return False


def load_vivisect() -> bool:
    try:
        import vivisect  # noqa: F401 unused import

        return True
    except ImportError:
        return False


def main():
    logging.basicConfig(level=logging.INFO)

    table = rich.table.Table()
    table.add_column("backend")
    table.add_column("already installed?")
    table.add_column("found?")
    table.add_column("loads?")

    if True:
        row = ["vivisect"]
        if is_vivisect_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append("False")

        row.append(str(load_vivisect()))
        table.add_row(*row)

    if True:
        row = ["Binary Ninja"]
        if is_binaryninja_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append(str(find_binaryninja() is not None))

        row.append(str(load_binaryninja()))
        table.add_row(*row)

    if True:
        row = ["IDA idalib"]
        if is_idalib_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append(str(find_idalib() is not None))

        row.append(str(load_idalib()))
        table.add_row(*row)

    rich.print(table)


if __name__ == "__main__":
    main()
