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

import pickle
from pathlib import Path
from unittest.mock import patch

import pytest
import envi.exc
import fixtures

from capa.loader import (
    CAPA_LOAD_VIV_WORKSPACE_ENV,
    CorruptFile,
    get_workspace,
    _load_viv_workspace,
)
from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_AUTO

EXECUTED: list[bool] = []


def _mark_executed():
    EXECUTED.append(True)


class _Payload:
    def __reduce__(self):
        return (_mark_executed, ())


def _write_pickle_viv(path: Path):
    path.write_bytes(b"VIV".ljust(8, b"\x00") + pickle.dumps([_Payload()], protocol=2))


def _write_msgpack_viv(path: Path):
    path.write_bytes(b"\xa8MSGVIV\x00\x00")


def _copy_sample(tmp_path: Path) -> Path:
    path = tmp_path / "pma.dll_"
    path.write_bytes((fixtures.CD / "data" / "Practical Malware Analysis Lab 01-01.dll_").read_bytes())
    return path


def test_segmentation_violation_handling():
    """
    Test that SegmentationViolation from vivisect is caught and
    converted to a CorruptFile exception.

    See #2794.
    """
    fake_path = Path("/tmp/fake_malformed.elf")

    with patch("capa.loader._load_viv_workspace") as mock_workspace:
        mock_workspace.side_effect = envi.exc.SegmentationViolation(
            0x30A4B8BD60,
        )

        with pytest.raises(CorruptFile, match="Invalid memory access"):
            get_workspace(fake_path, FORMAT_ELF, [])


def test_corrupt_pe_with_unrealistic_section_size_short_circuits():
    """
    Test that a PE with an unrealistically large section virtual size
    is caught early and raises CorruptFile before vivisect is invoked.

    See #1989.
    """
    fake_path = Path("/tmp/fake_corrupt.exe")

    with (
        patch("capa.loader._is_probably_corrupt_pe", return_value=True),
        patch("capa.loader._load_viv_workspace") as mock_workspace,
    ):
        with pytest.raises(CorruptFile, match="unrealistically large sections"):
            get_workspace(fake_path, FORMAT_PE, [])

        # vivisect should never have been called
        mock_workspace.assert_not_called()


@pytest.mark.parametrize("write", [_write_pickle_viv, _write_msgpack_viv])
@pytest.mark.parametrize("fmt", [FORMAT_AUTO, FORMAT_PE, FORMAT_ELF])
@pytest.mark.parametrize("name", ["sample.exe_", "sample.viv"])
def test_get_workspace_rejects_serialized_workspace_input(tmp_path, write, fmt, name):
    path = tmp_path / name
    write(path)

    EXECUTED.clear()
    with pytest.raises(UnsupportedFormatError):
        get_workspace(path, fmt, [])
    assert not EXECUTED


def test_load_viv_workspace_ignores_sibling_viv_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv(CAPA_LOAD_VIV_WORKSPACE_ENV, raising=False)
    path = _copy_sample(tmp_path)
    _write_pickle_viv(Path(f"{path}.viv"))

    EXECUTED.clear()
    vw = _load_viv_workspace(path, FORMAT_AUTO)
    assert not EXECUTED
    assert vw.getMeta("Format") == "pe"


@pytest.mark.parametrize("value", ["", "0", "false", "no"])
def test_load_viv_workspace_ignores_sibling_viv_when_not_opted_in(tmp_path, monkeypatch, value):
    monkeypatch.setenv(CAPA_LOAD_VIV_WORKSPACE_ENV, value)
    path = _copy_sample(tmp_path)
    _write_pickle_viv(Path(f"{path}.viv"))

    EXECUTED.clear()
    _load_viv_workspace(path, FORMAT_AUTO)
    assert not EXECUTED


def test_load_viv_workspace_loads_sibling_viv_when_allowed(tmp_path, monkeypatch):
    path = _copy_sample(tmp_path)

    monkeypatch.delenv(CAPA_LOAD_VIV_WORKSPACE_ENV, raising=False)
    vw = _load_viv_workspace(path, FORMAT_AUTO)
    vw.setMeta("capa_test_marker", True)
    vw.saveWorkspace()
    assert Path(f"{path}.viv").exists()

    vw = _load_viv_workspace(path, FORMAT_AUTO)
    assert not vw.getMeta("capa_test_marker")

    monkeypatch.setenv(CAPA_LOAD_VIV_WORKSPACE_ENV, "1")
    vw = _load_viv_workspace(path, FORMAT_AUTO)
    assert vw.getMeta("capa_test_marker")
