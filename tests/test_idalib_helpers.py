# Copyright 2025 Google LLC
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
import json
import shutil
from pathlib import Path

from capa.features.extractors.ida.idalib import _get_install_dir_from_config, _locate_idalib_in_install_dir

LIBNAME = {
    "win32": "idalib.dll",
    "linux": "libidalib.so",
    "linux2": "libidalib.so",
    "darwin": "libidalib.dylib",
}[sys.platform]


# ---------------------------------------------------------------------------
# _get_install_dir_from_config
# ---------------------------------------------------------------------------


def test_get_install_dir_from_config_happy_path(tmp_path):
    install_dir = tmp_path / "ida"
    config = {"Paths": {"ida-install-dir": str(install_dir)}}
    config_path = tmp_path / "ida-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    result = _get_install_dir_from_config(config_path)

    assert result == install_dir


def test_get_install_dir_from_config_missing_file(tmp_path):
    config_path = tmp_path / "ida-config.json"

    result = _get_install_dir_from_config(config_path)

    assert result is None


def test_get_install_dir_from_config_invalid_json(tmp_path):
    config_path = tmp_path / "ida-config.json"
    config_path.write_text("{not valid json", encoding="utf-8")

    result = _get_install_dir_from_config(config_path)

    assert result is None


def test_get_install_dir_from_config_missing_paths_key(tmp_path):
    config = {"OtherSection": {"something": "value"}}
    config_path = tmp_path / "ida-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    result = _get_install_dir_from_config(config_path)

    assert result is None


def test_get_install_dir_from_config_missing_install_dir_key(tmp_path):
    config = {"Paths": {"other-key": "/some/path"}}
    config_path = tmp_path / "ida-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    result = _get_install_dir_from_config(config_path)

    assert result is None


def test_get_install_dir_from_config_empty_install_dir(tmp_path):
    config = {"Paths": {"ida-install-dir": ""}}
    config_path = tmp_path / "ida-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    result = _get_install_dir_from_config(config_path)

    assert result is None


# ---------------------------------------------------------------------------
# _locate_idalib_in_install_dir
# ---------------------------------------------------------------------------


def _populate_install_dir(install_dir: Path) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    (install_dir / "ida.hlp").write_bytes(b"")
    (install_dir / LIBNAME).write_bytes(b"")
    idapro_dir = install_dir / "idalib" / "python" / "idapro"
    idapro_dir.mkdir(parents=True)
    (idapro_dir / "__init__.py").write_bytes(b"")


def test_locate_idalib_happy_path(tmp_path):
    install_dir = tmp_path / "ida"
    _populate_install_dir(install_dir)

    result = _locate_idalib_in_install_dir(install_dir)

    assert result == install_dir / "idalib" / "python"


def test_locate_idalib_nonexistent_install_dir(tmp_path):
    install_dir = tmp_path / "ida_missing"

    result = _locate_idalib_in_install_dir(install_dir)

    assert result is None


def test_locate_idalib_missing_ida_hlp(tmp_path):
    install_dir = tmp_path / "ida"
    _populate_install_dir(install_dir)
    (install_dir / "ida.hlp").unlink()

    result = _locate_idalib_in_install_dir(install_dir)

    assert result is None


def test_locate_idalib_missing_library_file(tmp_path):
    install_dir = tmp_path / "ida"
    _populate_install_dir(install_dir)
    (install_dir / LIBNAME).unlink()

    result = _locate_idalib_in_install_dir(install_dir)

    assert result is None


def test_locate_idalib_missing_python_dir(tmp_path):
    install_dir = tmp_path / "ida"
    _populate_install_dir(install_dir)
    shutil.rmtree(install_dir / "idalib")

    result = _locate_idalib_in_install_dir(install_dir)

    assert result is None


def test_locate_idalib_missing_idapro_init(tmp_path):
    install_dir = tmp_path / "ida"
    _populate_install_dir(install_dir)
    (install_dir / "idalib" / "python" / "idapro" / "__init__.py").unlink()

    result = _locate_idalib_in_install_dir(install_dir)

    assert result is None
