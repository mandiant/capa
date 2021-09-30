# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import capa.render.utils
from capa.features.common import Feature


class API(Feature):
    def __init__(self, name: str, description=None):
        # Downcase library name if given
        if "." in name:
            modname, _, impname = name.rpartition(".")
            name = modname.lower() + "." + impname

        super(API, self).__init__(name, description=description)


class Number(Feature):
    def __init__(self, value: int, bitness=None, description=None):
        super(Number, self).__init__(value, bitness=bitness, description=description)

    def get_value_str(self):
        return capa.render.utils.hex(self.value)


class Offset(Feature):
    def __init__(self, value: int, bitness=None, description=None):
        super(Offset, self).__init__(value, bitness=bitness, description=description)

    def get_value_str(self):
        return capa.render.utils.hex(self.value)


class Mnemonic(Feature):
    def __init__(self, value: str, description=None):
        super(Mnemonic, self).__init__(value, description=description)
