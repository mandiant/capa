# Copyright 2024 Google LLC
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
import json
import logging
import importlib.util
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# The idalib activation script shipped with IDA creates ida-config.json.
IDALIB_ACTIVATION_SCRIPT = "python3 <ida-install-dir>/idalib/python/py-activate-idalib.py"


def is_idalib_installed() -> bool:
    try:
        return importlib.util.find_spec("idapro") is not None
    except ModuleNotFoundError:
        return False


def get_idalib_user_config_path() -> Optional[Path]:
    """Get the path to the user's ida-config.json based on platform following IDA's user directories."""
    # derived from `py-activate-idalib.py` from IDA v9.0 Beta 4

    if sys.platform == "win32":
        # On Windows, use the %APPDATA%\Hex-Rays\IDA Pro directory
        appdata = os.getenv("APPDATA", "")
        config_dir = Path(appdata) / "Hex-Rays" / "IDA Pro"
    else:
        # On macOS and Linux, use ~/.idapro
        config_dir = Path.home() / ".idapro"

    user_config_path = config_dir / "ida-config.json"
    if not user_config_path.exists():
        return None
    return user_config_path


def _get_install_dir_from_config(config_path: Path) -> Optional[Path]:
    """Read the ida-install-dir from the idalib JSON config."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        logger.error("failed to read IDA Pro user configuration %s: %s", config_path, e)
        return None

    try:
        ida_install_dir = config["Paths"]["ida-install-dir"]
    except KeyError:
        ida_install_dir = ""

    if not ida_install_dir:
        logger.error(
            "%s does not contain a valid Paths.ida-install-dir entry. "  # noqa: G003 [logging statement uses +]
            + "Re-run the idalib activation script to configure it: %s",
            config_path,
            IDALIB_ACTIVATION_SCRIPT,
        )
        return None

    return Path(ida_install_dir)


def _locate_idalib_in_install_dir(ida_install_dir: Path) -> Optional[Path]:
    """Given an IDA installation directory, verify it contains idalib and return the Python path."""
    if not ida_install_dir.exists():
        return None

    libname = {
        "win32": "idalib.dll",
        "linux": "libidalib.so",
        "linux2": "libidalib.so",
        "darwin": "libidalib.dylib",
    }[sys.platform]

    if not (ida_install_dir / "ida.hlp").is_file():
        return None

    if not (ida_install_dir / libname).is_file():
        return None

    idalib_path = ida_install_dir / "idalib" / "python"
    if not idalib_path.exists():
        return None

    if not (idalib_path / "idapro" / "__init__.py").is_file():
        return None

    return idalib_path


def find_idalib() -> Optional[Path]:
    config_path = get_idalib_user_config_path()
    if not config_path:
        if sys.platform == "win32":
            config_location = "%APPDATA%\\Hex-Rays\\IDA Pro\\ida-config.json"
        else:
            config_location = "~/.idapro/ida-config.json"
        logger.error(
            "IDA Pro user configuration not found at %s. "  # noqa: G003 [logging statement uses +]
            + "To set up idalib, run the activation script: %s",
            config_location,
            IDALIB_ACTIVATION_SCRIPT,
        )
        return None

    ida_install_dir = _get_install_dir_from_config(config_path)
    if not ida_install_dir:
        return None

    idalib_path = _locate_idalib_in_install_dir(ida_install_dir)
    if not idalib_path:
        logger.error(
            "idalib not found in IDA installation at %s. "  # noqa: G003 [logging statement uses +]
            + "Ensure idalib is set up by running: %s",
            ida_install_dir,
            IDALIB_ACTIVATION_SCRIPT,
        )
        return None

    return idalib_path


def has_idalib() -> bool:
    if is_idalib_installed():
        logger.debug("found installed IDA idalib API")
        return True

    logger.debug("IDA idalib API not installed, searching...")

    idalib_path = find_idalib()
    if not idalib_path:
        logger.debug("failed to find IDA idalib installation")

    logger.debug("found IDA idalib API: %s", idalib_path)
    return idalib_path is not None


def load_idalib() -> bool:
    try:
        import idapro

        return True
    except ImportError:
        idalib_path = find_idalib()
        if not idalib_path:
            return False

        sys.path.append(idalib_path.absolute().as_posix())
        try:
            import idapro  # noqa: F401 unused import

            return True
        except ImportError:
            return False
