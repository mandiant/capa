# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import textwrap

from capa.features.extractors.vmray.models import Param, FunctionCall, xml_to_dict


def test_vmray_model_call():
    call_xml = textwrap.dedent(
        """
        <fncall ts="9044" fncall_id="18" process_id="1" thread_id="1" name="sys_time" addr="0xaaaaaaaaaaaaaaaa" from="0xaaaaaaaa">
            <kernel/>
            <in>
                <param name="tloc" type="unknown" value="0x0"/>
            </in>
            <out>
                <param name="ret_val" type="unknown" value="0xaaaaaaaa"/>
            </out>
        </fncall>
        """
    )
    call: FunctionCall = FunctionCall.model_validate(xml_to_dict(call_xml)["fncall"])

    assert call.fncall_id == 18
    assert call.process_id == 1
    assert call.thread_id == 1
    assert call.name == "time"
    assert call.params_in is not None
    assert call.params_out is not None


def test_vmray_model_call_param():
    param_xml = textwrap.dedent(
        """
        <param name="addrlen" type="signed_32bit" value="16"/>
        """
    )
    param: Param = Param.model_validate(xml_to_dict(param_xml)["param"])

    assert param.value == "16"


def test_vmray_model_call_param_deref():
    param_xml = textwrap.dedent(
        """
        <param name="buf" type="ptr" value="0xaaaaaaaa">
            <deref type="str" value="Hello world"/>
        </param>
        """
    )
    param: Param = Param.model_validate(xml_to_dict(param_xml)["param"])

    assert param.deref is not None
    assert param.deref.value == "Hello world"
