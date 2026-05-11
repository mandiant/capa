# Copyright 2022 Google LLC
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

import pytest

import capa.rules


def test_dynamic_span_scope_thread_subscope():
    rule = textwrap.dedent("""
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - thread:
                        - string: "foo"
        """)

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(rule)
