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

from enum import Enum

from capa.helpers import assert_never


class ComType(Enum):
    CLASS = "class"
    INTERFACE = "interface"


COM_PREFIXES = {
    ComType.CLASS: "CLSID_",
    ComType.INTERFACE: "IID_",
}


def load_com_database(com_type: ComType) -> dict[str, list[str]]:
    # lazy load these python files since they are so large.
    # that is, don't load them unless a COM feature is being handled.
    import capa.features.com.classes
    import capa.features.com.interfaces

    if com_type == ComType.CLASS:
        return capa.features.com.classes.COM_CLASSES
    elif com_type == ComType.INTERFACE:
        return capa.features.com.interfaces.COM_INTERFACES
    else:
        assert_never(com_type)
