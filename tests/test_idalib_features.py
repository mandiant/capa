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

import pytest
import fixtures

from capa.features.file import FunctionName
from capa.features.insn import API
from capa.features.common import Characteristic

logger = logging.getLogger(__name__)

try:
    if True:
        # in order to use idalib, we have to import the idapro package
        # which manipulates the search path as a side effect.
        # we have to do this before importing ida_* packages.
        # but isort wants to put idapro after ida_kernwin, so we use
        # this dumb branch to keep the ordering correct.
        import idapro  # noqa: F401 [imported but unused]
    import ida_kernwin

    kernel_version: str = ida_kernwin.get_kernel_version()
    idalib_present = True
except ImportError:
    idalib_present = False
    kernel_version = "0.0"


@pytest.mark.skipif(
    idalib_present is False,
    reason="Skip idalib tests if the idalib Python API is not installed",
)
@fixtures.parametrize_backend_feature_fixtures(
    fixtures.BackendFeaturePolicy(
        name="idalib",
        include_tags={"static"},
        exclude_tags={"dotnet", "ghidra"},
    )
)
def test_idalib_features(feature_fixture):
    # apply runtime-conditional xfails for specific IDA versions.
    # version-specific behavior stays in the test body because it
    # depends on the installed IDA, not on the fixture data.
    sample_name = feature_fixture.sample_path.name
    statement = feature_fixture.statement

    if kernel_version in {"9.0", "9.1"} and sample_name.startswith("2bf18d"):
        if isinstance(statement, (API, FunctionName)) and statement.value == "__libc_connect":
            # see discussion here: https://github.com/mandiant/capa/pull/2742#issuecomment-3674146335
            #
            # > i confirmed that there were changes in 9.2 related to the ELF loader handling names,
            # > so I think its reasonable to conclude that 9.1 and older had a bug that
            # > prevented this name from surfacing.
            pytest.xfail(f"IDA {kernel_version} does not extract all ELF symbols")

    if kernel_version in {"9.0"} and sample_name.startswith("Practical Malware Analysis Lab 12-04.exe_"):
        if isinstance(statement, Characteristic) and statement.value == "embedded pe":
            # see discussion here: https://github.com/mandiant/capa/pull/2742#issuecomment-3667086165
            #
            # idalib for IDA 9.0 doesn't support argv arguments, so we can't ask that resources are loaded
            pytest.xfail("idalib 9.0 does not support loading resource segments")

    with fixtures.get_idalib_extractor(feature_fixture.sample_path) as extractor:
        fixtures.run_feature_fixture(extractor, feature_fixture)


@pytest.mark.skipif(
    idalib_present is False,
    reason="Skip idalib tests if the idalib Python API is not installed",
)
def test_idalib_compatibility_helpers():
    import ida_funcs

    import capa.features.extractors.ida.helpers as helpers

    sample = fixtures.CD / "data" / "kernel32-64.dll_"
    with fixtures.get_idalib_extractor(sample) as extractor:
        functions = list(helpers.get_functions())
        assert functions

        fh = functions[0]
        func_ea = fh.inner.start_ea
        assert func_ea == fh.address
        assert isinstance(helpers.get_func_flags(func_ea), int)

        blocks = list(helpers.get_function_blocks(fh.inner))
        assert blocks
        assert all(bb.start_ea < bb.end_ea for bb in blocks)

        assert extractor.get_function(func_ea).inner.start_ea == func_ea

        segments = list(helpers.get_segments())
        assert segments
        assert all(helpers.get_segment_name(seg) for seg in segments)
        assert all(isinstance(helpers.get_segment_type(seg), int) for seg in segments)

        seg = segments[0]
        assert helpers.get_segment_start(seg.start_ea) == seg.start_ea

        # exercise the function comment compatibility helper, then restore the original comment
        original = helpers.get_func_comment(func_ea, False) or ""
        comment = "Alternative name is 'capa_compat_test'"
        if hasattr(ida_funcs, "set_func_cmt_ea"):
            ida_funcs.set_func_cmt_ea(func_ea, comment, False)
        else:
            ida_funcs.set_func_cmt(ida_funcs.get_func(func_ea), comment, False)

        try:
            assert "capa_compat_test" in list(helpers.get_function_alternative_names(func_ea))
        finally:
            if hasattr(ida_funcs, "set_func_cmt_ea"):
                ida_funcs.set_func_cmt_ea(func_ea, original, False)
            else:
                ida_funcs.set_func_cmt(ida_funcs.get_func(func_ea), original, False)
