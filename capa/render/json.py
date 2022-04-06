# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import json

from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.render.result_document import convert_capabilities_to_result_document


class CapaJsonObjectEncoder(json.JSONEncoder):
    """JSON encoder that emits Python sets as sorted lists"""

    def default(self, obj):
        if isinstance(obj, (list, dict, int, float, bool, type(None))) or isinstance(obj, str):
            return json.JSONEncoder.default(self, obj)
        elif isinstance(obj, set):
            return list(sorted(obj))
        else:
            # probably will TypeError
            return json.JSONEncoder.default(self, obj)


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    return json.dumps(
        convert_capabilities_to_result_document(meta, rules, capabilities),
        cls=CapaJsonObjectEncoder,
        sort_keys=True,
    )
