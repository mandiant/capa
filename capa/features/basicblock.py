# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from capa.features.common import Feature


class BasicBlock(Feature):
    def __init__(self):
        super(BasicBlock, self).__init__(None)

    def __str__(self):
        return "basic block"

    def get_value_str(self):
        return ""

    def freeze_serialize(self):
        return (self.__class__.__name__, [])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls()
