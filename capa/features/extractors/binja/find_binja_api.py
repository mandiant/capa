# Copyright 2023 Google LLC
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

import os
import sys
import logging
import subprocess
import importlib.util
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# When the script gets executed as a standalone executable (via PyInstaller), `import binaryninja` does not work because
# we have excluded the binaryninja module in `pyinstaller.spec`. The trick here is to call the system Python and try
# to find out the path of the binaryninja module that has been installed.
# Note, including the binaryninja module in the `pyinstaller.spec` would not work, since the binaryninja module tries to
# find the binaryninja core e.g., `libbinaryninjacore.dylib`, using a relative path. And this does not work when the
# binaryninja module is extracted by the PyInstaller.
CODE = r"""
from pathlib import Path
from importlib import util
spec = util.find_spec('binaryninja')
if spec is not None:
    if len(spec.submodule_search_locations) > 0:
        path = Path(spec.submodule_search_locations[0])
        # encode the path with utf8 then convert to hex, make sure it can be read and restored properly
        print(str(path.parent).encode('utf8').hex())
"""


def find_binaryninja_path_via_subprocess() -> Optional[Path]:
    raw_output = subprocess.check_output(["python", "-c", CODE]).decode("ascii").strip()
    output = bytes.fromhex(raw_output).decode("utf8")
    if not output.strip():
        return None
    return Path(output)


def get_desktop_entry(name: str) -> Optional[Path]:
    """
    Find the path for the given XDG Desktop Entry name.

    Like:

        >> get_desktop_entry("com.vector35.binaryninja.desktop")
        Path("~/.local/share/applications/com.vector35.binaryninja.desktop")
    """
    assert sys.platform in ("linux", "linux2")
    assert name.endswith(".desktop")

    data_dirs = os.environ.get("XDG_DATA_DIRS", "/usr/share") + f":{Path.home()}/.local/share"
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


def validate_binaryninja_path(binaryninja_path: Path) -> bool:
    if not binaryninja_path:
        return False

    module_path = binaryninja_path / "python"
    if not module_path.is_dir():
        return False

    if not (module_path / "binaryninja" / "__init__.py").is_file():
        return False

    return True


def find_binaryninja() -> Optional[Path]:
    binaryninja_path = find_binaryninja_path_via_subprocess()
    if not binaryninja_path or not validate_binaryninja_path(binaryninja_path):
        if sys.platform == "linux" or sys.platform == "linux2":
            # ok
            logger.debug("detected OS: linux")
        elif sys.platform == "darwin":
            logger.warning("unsupported platform to find Binary Ninja: %s", sys.platform)
            return None
        elif sys.platform == "win32":
            logger.warning("unsupported platform to find Binary Ninja: %s", sys.platform)
            return None
        else:
            logger.warning("unsupported platform to find Binary Ninja: %s", sys.platform)
            return None

        desktop_entry = get_desktop_entry("com.vector35.binaryninja.desktop")
        if not desktop_entry:
            logger.debug("failed to find Binary Ninja application")
            return None
        logger.debug("found Binary Ninja application: %s", desktop_entry)

        binaryninja_path = get_binaryninja_path(desktop_entry)
        if not binaryninja_path:
            logger.debug("failed to determine Binary Ninja installation path")
            return None

        if not validate_binaryninja_path(binaryninja_path):
            logger.debug("failed to validate Binary Ninja installation")
            return None

    logger.debug("found Binary Ninja installation: %s", binaryninja_path)

    return binaryninja_path / "python"


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


if __name__ == "__main__":
    print(find_binaryninja_path_via_subprocess())
