# Copyright 2021 Google LLC
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

import capa.rules
import capa.engine
import capa.optimizer
import capa.features.common
from capa.engine import Or, And
from capa.features.insn import Mnemonic
from capa.features.common import Arch, Substring


def test_optimizer_order():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - substring: "foo"
                    - arch: amd64
                    - mnemonic: cmp
                    - and:
                      - bytes: 3
                      - offset: 2
                    - or:
                      - number: 1
                      - offset: 4
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # before optimization
    children = list(r.statement.get_children())
    assert isinstance(children[0], Substring)
    assert isinstance(children[1], Arch)
    assert isinstance(children[2], Mnemonic)
    assert isinstance(children[3], And)
    assert isinstance(children[4], Or)

    # after optimization
    capa.optimizer.optimize_rules([r])
    children = list(r.statement.get_children())

    # cost: 0
    assert isinstance(children[0], Arch)
    # cost: 1
    assert isinstance(children[1], Mnemonic)
    # cost: 2
    assert isinstance(children[2], Substring)
    # cost: 3
    assert isinstance(children[3], Or)
    # cost: 4
    assert isinstance(children[4], And)
