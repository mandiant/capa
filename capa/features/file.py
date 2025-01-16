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


from capa.features.common import Feature


class Export(Feature):
    def __init__(self, value: str, description=None):
        # value is export name
        super().__init__(value, description=description)


class Import(Feature):
    def __init__(self, value: str, description=None):
        # value is import name
        super().__init__(value, description=description)


class Section(Feature):
    def __init__(self, value: str, description=None):
        # value is section name
        super().__init__(value, description=description)


class FunctionName(Feature):
    """recognized name for statically linked function"""

    def __init__(self, name: str, description=None):
        # value is function name
        super().__init__(name, description=description)
        # override the name property set by `capa.features.Feature`
        # that would be `functionname` (note missing dash)
        self.name = "function-name"
