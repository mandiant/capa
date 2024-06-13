# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict


class VMRayAnalysis:
    def __init__(self, sv2, flog):
        self.sv2 = sv2  # logs/summary_v2.json
        self.flog = flog  # logs/flog.xml
        self.exports: Dict[int, str] = {}
        self.imports: Dict[int, str] = {}

        self.sample_file_name: str
        self.sample_file_analysis = None
        self.sample_file_static_data = None

        self._find_sample_file()
        self._compute_exports()

    def _find_sample_file(self):
        for k, v in self.sv2.files.items():
            if v.is_sample:
                self.sample_file_name = k
                self.sample_file_analysis = v

                if v.ref_static_data:
                    self.sample_file_static_data = self.sv2.static_data.get(v.ref_static_data.path[1])

                break

    def _compute_exports(self):
        if not self.sample_file_static_data:
            return

        if not self.sample_file_static_data.pe:
            return

        pe = self.sample_file_static_data.pe

        if pe.exports:
            for export in pe.exports:
                self.exports[export.address] = export.api.name
