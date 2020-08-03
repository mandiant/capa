# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from capa.features import Feature


class Export(Feature):
    def __init__(self, value, description=None):
        # value is export name
        super(Export, self).__init__(value, description=description)


class Import(Feature):
    def __init__(self, value, description=None):
        # value is import name
        super(Import, self).__init__(value, description=description)


class Section(Feature):
    def __init__(self, value, description=None):
        # value is section name
        super(Section, self).__init__(value, description=description)
