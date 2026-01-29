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
from capa.features.common import FORMAT_ELF


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
