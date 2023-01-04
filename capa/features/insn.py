# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import abc
from typing import Union, Optional

import capa.helpers
from capa.features.common import VALID_FEATURE_ACCESS, Feature


def hex(n: int) -> str:
    """render the given number using upper case hex, like: 0x123ABC"""
    if n < 0:
        return "-0x%X" % (-n)
    else:
        return "0x%X" % n


class API(Feature):
    def __init__(self, name: str, description=None):
        super().__init__(name, description=description)


class _AccessFeature(Feature, abc.ABC):
    # superclass: don't use directly
    def __init__(self, value: str, access: Optional[str] = None, description: Optional[str] = None):
        super().__init__(value, description=description)
        if access is not None:
            if access not in VALID_FEATURE_ACCESS:
                raise ValueError("%s access type %s not valid" % (self.name, access))
        self.access = access

    def __hash__(self):
        return hash((self.name, self.value, self.access))

    def __eq__(self, other):
        return super().__eq__(other) and self.access == other.access

    def get_name_str(self) -> str:
        if self.access is not None:
            return f"{self.name}/{self.access}"
        return self.name


class Property(_AccessFeature):
    def __init__(self, value: str, access: Optional[str] = None, description=None):
        super().__init__(value, access=access, description=description)


class Number(Feature):
    def __init__(self, value: Union[int, float], description=None):
        super().__init__(value, description=description)

    def get_value_str(self):
        if isinstance(self.value, int):
            return capa.helpers.hex(self.value)
        elif isinstance(self.value, float):
            return str(self.value)
        else:
            raise ValueError("invalid value type")


# max recognized structure size (and therefore, offset size)
MAX_STRUCTURE_SIZE = 0x10000


class Offset(Feature):
    def __init__(self, value: int, description=None):
        super().__init__(value, description=description)

    def get_value_str(self):
        assert isinstance(self.value, int)
        return hex(self.value)


class Mnemonic(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)


# max number of operands to consider for a given instruction.
# since we only support Intel and .NET, we can assume this is 3
# which covers cases up to e.g. "vinserti128 ymm0,ymm0,ymm5,1"
MAX_OPERAND_COUNT = 4
MAX_OPERAND_INDEX = MAX_OPERAND_COUNT - 1


class _Operand(Feature, abc.ABC):
    # superclass: don't use directly
    # subclasses should set self.name and provide the value string formatter
    def __init__(self, index: int, value: int, description=None):
        super().__init__(value, description=description)
        self.index = index

    def __hash__(self):
        return hash((self.name, self.value))

    def __eq__(self, other):
        return super().__eq__(other) and self.index == other.index


class OperandNumber(_Operand):
    # cached names so we don't do extra string formatting every ctor
    NAMES = ["operand[%d].number" % i for i in range(MAX_OPERAND_COUNT)]

    # operand[i].number: 0x12
    def __init__(self, index: int, value: int, description=None):
        super().__init__(index, value, description=description)
        self.name = self.NAMES[index]

    def get_value_str(self) -> str:
        assert isinstance(self.value, int)
        return hex(self.value)


class OperandOffset(_Operand):
    # cached names so we don't do extra string formatting every ctor
    NAMES = ["operand[%d].offset" % i for i in range(MAX_OPERAND_COUNT)]

    # operand[i].offset: 0x12
    def __init__(self, index: int, value: int, description=None):
        super().__init__(index, value, description=description)
        self.name = self.NAMES[index]

    def get_value_str(self) -> str:
        assert isinstance(self.value, int)
        return hex(self.value)
