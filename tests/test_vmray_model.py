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

import textwrap

from capa.features.extractors.vmray.models import (
    Param,
    PEFile,
    ElfFile,
    FunctionCall,
    AnalysisMetadata,
    hexint,
    xml_to_dict,
)


def test_vmray_model_param():
    param_str = textwrap.dedent(
        """
        <param name="addrlen" type="signed_32bit" value="16"/>
        """
    )
    param: Param = Param.model_validate(xml_to_dict(param_str)["param"])

    assert param.value is not None
    assert hexint(param.value) == 16


def test_vmray_model_param_deref():
    param_str = textwrap.dedent(
        """
        <param name="buf" type="ptr" value="0xaaaaaaaa">
            <deref type="str" value="Hello world"/>
        </param>
        """
    )
    param: Param = Param.model_validate(xml_to_dict(param_str)["param"])

    assert param.deref is not None
    assert param.deref.value == "Hello world"


def test_vmray_model_function_call():
    function_call_str = textwrap.dedent(
        """
        <fncall fncall_id="18" process_id="1" thread_id="1" name="sys_time">
            <in>
                <param name="tloc" type="unknown" value="0x0"/>
            </in>
            <out>
                <param name="ret_val" type="unknown" value="0xaaaaaaaa"/>
            </out>
        </fncall>
        """
    )
    function_call: FunctionCall = FunctionCall.model_validate(xml_to_dict(function_call_str)["fncall"])

    assert function_call.fncall_id == 18
    assert function_call.process_id == 1
    assert function_call.thread_id == 1
    assert function_call.name == "time"

    assert function_call.params_in is not None
    assert function_call.params_in.params[0].value is not None
    assert hexint(function_call.params_in.params[0].value) == 0

    assert function_call.params_out is not None
    assert function_call.params_out.params[0].value is not None
    assert hexint(function_call.params_out.params[0].value) == 2863311530


def test_vmray_model_analysis_metadata():
    analysis_metadata: AnalysisMetadata = AnalysisMetadata.model_validate_json(
        """
        {
            "sample_type": "Linux ELF Executable (x86-64)",
            "submission_filename": "abcd1234"
        }
        """
    )

    assert analysis_metadata.sample_type == "Linux ELF Executable (x86-64)"
    assert analysis_metadata.submission_filename == "abcd1234"


def test_vmray_model_elffile():
    elffile: ElfFile = ElfFile.model_validate_json(
        """
        {
            "sections": [
                {
                    "header": {
                        "sh_name": "abcd1234",
                        "sh_addr": 2863311530
                    }
                }
            ]
        }
        """
    )

    assert elffile.sections[0].header.sh_name == "abcd1234"
    assert elffile.sections[0].header.sh_addr == 2863311530


def test_vmray_model_pefile():
    pefile: PEFile = PEFile.model_validate_json(
        """
        {
            "basic_info": {
                "image_base": 2863311530
            },
            "imports": [
            {
                "apis": [
                    {
                        "address": 2863311530,
                        "api": {
                            "name": "Sleep"
                        }
                    }
                ],
                "dll": "KERNEL32.dll"
                }
            ],
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": 2863311530
                }
            ],
            "exports": [
                {
                    "api": {
                        "name": "HelloWorld",
                        "ordinal": 10
                    },
                    "address": 2863311530
                }
            ]
        }
        """
    )

    assert pefile.basic_info.image_base == 2863311530

    assert pefile.imports[0].dll == "KERNEL32.dll"
    assert pefile.imports[0].apis[0].address == 2863311530
    assert pefile.imports[0].apis[0].api.name == "Sleep"

    assert pefile.sections[0].name == ".text"
    assert pefile.sections[0].virtual_address == 2863311530

    assert pefile.exports[0].address == 2863311530
    assert pefile.exports[0].api.name == "HelloWorld"
    assert pefile.exports[0].api.ordinal == 10
