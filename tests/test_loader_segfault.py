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

from pathlib import Path
from unittest.mock import patch

import pytest
import envi.exc

from capa.loader import CorruptFile, get_workspace
from capa.exceptions import AnalysisTimeoutError, UnsupportedArchError
from capa.features.common import FORMAT_PE, FORMAT_ELF


def test_segmentation_violation_handling():
    """
    Test that SegmentationViolation from vivisect is caught and
    converted to a CorruptFile exception.

    See #2794.
    """
    fake_path = Path("/tmp/fake_malformed.elf")

    with patch("viv_utils.getWorkspace") as mock_workspace:
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
        patch("viv_utils.getWorkspace") as mock_workspace,
    ):
        with pytest.raises(CorruptFile, match="unrealistically large sections"):
            get_workspace(fake_path, FORMAT_PE, [])

        # vivisect should never have been called
        mock_workspace.assert_not_called()


def test_elf_workspace_temporarily_disables_section_symbol_parsing():
    """
    Test that loading ELF in viv temporarily disables section-symbol parsing
    and restores the original parser after workspace creation.
    """
    import Elf

    fake_path = Path("/tmp/fake.elf")
    original = Elf.Elf._parseSectionSymbols
    observed = {}
    removed_modules = []

    class FakeWorkspace:
        metadata = {}

        def delFuncAnalysisModule(self, _):
            removed_modules.append(_)
            return None

        def analyze(self):
            return None

        def getFunctions(self):
            return []

    def fake_get_workspace(*args, **kwargs):
        observed["during"] = Elf.Elf._parseSectionSymbols
        return FakeWorkspace()

    with patch("viv_utils.getWorkspace", side_effect=fake_get_workspace):
        get_workspace(fake_path, FORMAT_ELF, [])

    assert observed["during"] is not original
    assert Elf.Elf._parseSectionSymbols is original
    assert "vivisect.analysis.generic.symswitchcase" in removed_modules
    assert "vivisect.analysis.elf.elfplt" in removed_modules
    assert "vivisect.analysis.amd64.emulation" in removed_modules
    assert "vivisect.analysis.generic.emucode" in removed_modules
    assert "vivisect.analysis.generic.noret" in removed_modules


def test_viv_module_not_found_maps_to_unsupported_arch():
    """
    Test that viv architecture-specific impapi import errors are converted
    to UnsupportedArchError.
    """
    fake_path = Path("/tmp/fake.elf")

    class FakeWorkspace:
        metadata = {}

        def delFuncAnalysisModule(self, _):
            return None

        def analyze(self):
            raise ModuleNotFoundError(
                "No module named 'vivisect.impapi.posix.a64'",
                name="vivisect.impapi.posix.a64",
            )

    with patch("viv_utils.getWorkspace", return_value=FakeWorkspace()):
        with pytest.raises(UnsupportedArchError):
            get_workspace(fake_path, FORMAT_ELF, [])


def test_viv_workspace_module_not_found_maps_to_unsupported_arch():
    """
    Test that impapi import failures during workspace creation are converted
    to UnsupportedArchError.
    """
    fake_path = Path("/tmp/fake.elf")
    err = ModuleNotFoundError(
        "No module named 'vivisect.impapi.posix.a64'",
        name="vivisect.impapi.posix.a64",
    )

    with patch("viv_utils.getWorkspace", side_effect=err):
        with pytest.raises(UnsupportedArchError):
            get_workspace(fake_path, FORMAT_ELF, [])


def test_elf_analysis_timeout_maps_to_corrupt_file():
    """
    Test that ELF analysis timeout is converted to CorruptFile.
    """
    fake_path = Path("/tmp/fake.elf")

    class FakeWorkspace:
        metadata = {}

        def delFuncAnalysisModule(self, _):
            return None

        def analyze(self):
            raise AnalysisTimeoutError("analysis exceeded timeout")

    with patch("viv_utils.getWorkspace", return_value=FakeWorkspace()):
        with pytest.raises(CorruptFile, match="analysis timed out"):
            get_workspace(fake_path, FORMAT_ELF, [])
