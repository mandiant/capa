import os
import sys
import json
import logging
import importlib.util
from typing import Optional
from pathlib import Path

import rich
import rich.table

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


def is_idalib_installed() -> bool:
    try:
        return importlib.util.find_spec("ida") is not None
    except ModuleNotFoundError:
        return False


def get_idalib_user_config_path() -> Optional[Path]:
    """Get the path to the user's config file based on platform following IDA's user directories."""
    # derived from `py-activate-idalib.py` from IDA v9.0 Beta 4

    if sys.platform == "win32":
        # On Windows, use the %APPDATA%\Hex-Rays\IDA Pro directory
        config_dir = Path(os.getenv("APPDATA")) / "Hex-Rays" / "IDA Pro"
    else:
        # On macOS and Linux, use ~/.idapro
        config_dir = Path.home() / ".idapro"

    # Return the full path to the config file (now in JSON format)
    user_config_path = config_dir / "ida-config.json"
    if not user_config_path.exists():
        return None
    return user_config_path


def find_idalib() -> Optional[Path]:
    config_path = get_idalib_user_config_path()
    if not config_path:
        return None

    config = json.loads(config_path.read_text(encoding="utf-8"))

    try:
        ida_install_dir = Path(config["Paths"]["ida-install-dir"])
    except KeyError:
        return None

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

    if not (idalib_path / "ida" / "__init__.py").is_file():
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
        import ida

        return True
    except ImportError:
        idalib_path = find_idalib()
        if not idalib_path:
            return False

        sys.path.append(idalib_path.absolute().as_posix())
        try:
            import ida  # noqa: F401 unused import

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
