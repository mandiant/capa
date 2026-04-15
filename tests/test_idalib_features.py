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
import logging

import fixtures
import pytest

import capa.features.extractors.ida.idalib
from capa.features.common import Characteristic
from capa.features.file import FunctionName
from capa.features.insn import API

logger = logging.getLogger(__name__)

idalib_present = capa.features.extractors.ida.idalib.has_idalib()
if idalib_present:
    try:
        import ida_kernwin
        import idapro  # noqa: F401 [imported but unused]

        kernel_version: str = ida_kernwin.get_kernel_version()
    except ImportError:
        idalib_present = False
        kernel_version = "0.0"
else:
    kernel_version = "0.0"


BACKEND = fixtures.BackendFeaturePolicy(
    name="idalib",
    get_extractor=fixtures.get_idalib_extractor,
    include_tags={"static"},
    exclude_tags={"dotnet", "ghidra"},
)


@pytest.mark.skipif(
    idalib_present is False,
    reason="Skip idalib tests if the idalib Python API is not installed",
)
@fixtures.parametrize_backend_feature_fixtures(BACKEND)
def test_idalib_features(feature_fixture):
    # apply runtime-conditional xfails for specific IDA versions.
    # version-specific behavior stays in the test body because it
    # depends on the installed IDA, not on the fixture data.
    sample_name = feature_fixture.sample_path.name
    statement = feature_fixture.statement

    if kernel_version in {"9.0", "9.1"} and sample_name.startswith("2bf18d"):
        if (
            isinstance(statement, (API, FunctionName))
            and statement.value == "__libc_connect"
        ):
            # see discussion here: https://github.com/mandiant/capa/pull/2742#issuecomment-3674146335
            #
            # > i confirmed that there were changes in 9.2 related to the ELF loader handling names,
            # > so I think its reasonable to conclude that 9.1 and older had a bug that
            # > prevented this name from surfacing.
            pytest.xfail(f"IDA {kernel_version} does not extract all ELF symbols")

    if kernel_version in {"9.0"} and sample_name.startswith(
        "Practical Malware Analysis Lab 12-04.exe_"
    ):
        if isinstance(statement, Characteristic) and statement.value == "embedded pe":
            # see discussion here: https://github.com/mandiant/capa/pull/2742#issuecomment-3667086165
            #
            # idalib for IDA 9.0 doesn't support argv arguments, so we can't ask that resources are loaded
            pytest.xfail("idalib 9.0 does not support loading resource segments")

    try:
        fixtures.run_feature_fixture(BACKEND, feature_fixture)
    finally:
        import idapro

        logger.debug("closing database...")
        idapro.close_database(save=False)
        logger.debug("closed database.")
