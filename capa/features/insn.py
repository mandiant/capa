# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import abc

import capa.render.utils
from capa.features.common import Feature


class API(Feature):
    def __init__(self, name: str, description=None):
        super(API, self).__init__(name, description=description)


class Number(Feature):
    def __init__(self, value: int, description=None):
        super(Number, self).__init__(value, description=description)

    def get_value_str(self):
        return capa.render.utils.hex(self.value)


# max recognized structure size (and therefore, offset size)
MAX_STRUCTURE_SIZE = 0x10000


class Offset(Feature):
    def __init__(self, value: int, description=None):
        super(Offset, self).__init__(value, description=description)

    def get_value_str(self):
        return capa.render.utils.hex(self.value)


class Mnemonic(Feature):
    def __init__(self, value: str, description=None):
        super(Mnemonic, self).__init__(value, description=description)


# max number of operands to consider for a given instrucion.
# since we only support Intel and .NET, we can assume this is 3
# which covers cases up to e.g. "vinserti128 ymm0,ymm0,ymm5,1"
MAX_OPERAND_COUNT = 4
MAX_OPERAND_INDEX = MAX_OPERAND_COUNT - 1


class _Operand(Feature, abc.ABC):
    # superclass: don't use directly
    # subclasses should set self.name and provide the value string formatter
    def __init__(self, index: int, value: int, description=None):
        super(_Operand, self).__init__(value, description=description)
        self.index = index

    def __hash__(self):
        return hash((self.name, self.value))

    def __eq__(self, other):
        return super().__eq__(other) and self.index == other.index

    def freeze_serialize(self):
        return (self.__class__.__name__, [self.index, self.value])


class OperandNumber(_Operand):
    # cached names so we don't do extra string formatting every ctor
    NAMES = ["operand[%d].number" % i for i in range(MAX_OPERAND_COUNT)]

    # operand[i].number: 0x12
    def __init__(self, index: int, value: int, description=None):
        super(OperandNumber, self).__init__(index, value, description=description)
        self.name = self.NAMES[index]

    def get_value_str(self) -> str:
        assert isinstance(self.value, int)
        return capa.render.utils.hex(self.value)


class OperandOffset(_Operand):
    # cached names so we don't do extra string formatting every ctor
    NAMES = ["operand[%d].offset" % i for i in range(MAX_OPERAND_COUNT)]

    # operand[i].offset: 0x12
    def __init__(self, index: int, value: int, description=None):
        super(OperandOffset, self).__init__(index, value, description=description)
        self.name = self.NAMES[index]

    def get_value_str(self) -> str:
        assert isinstance(self.value, int)
        return capa.render.utils.hex(self.value)
