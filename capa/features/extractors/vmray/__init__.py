# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict

from capa.exceptions import UnsupportedFormatError
from capa.features.extractors.vmray.models import File, Analysis, SummaryV2, StaticData


class VMRayAnalysis:
    def __init__(self, sv2: SummaryV2, flog: Analysis):
        self.sv2 = sv2  # logs/summary_v2.json
        self.flog = flog  # logs/flog.xml
        self.exports: Dict[int, str] = {}
        self.imports: Dict[int, str] = {}
        self.sections: Dict[int, str] = {}
        self.base_address: int

        self.sample_file_name: str
        self.sample_file_analysis: File
        self.sample_file_static_data: StaticData

        self._find_sample_file()
        self._compute_base_address()
        self._compute_exports()
        self._compute_sections()

        if not self.sample_file_static_data.pe:
            raise UnsupportedFormatError("VMRay feature extractor only supports PE at this time")

    def _find_sample_file(self):
        for file_name, file_analysis in self.sv2.files.items():
            if file_analysis.is_sample:
                # this indicates the sample submitted for analysis??
                self.sample_file_name = file_name
                self.sample_file_analysis = file_analysis

                if file_analysis.ref_static_data:
                    self.sample_file_static_data = self.sv2.static_data[file_analysis.ref_static_data.path[1]]

                break

    def _compute_base_address(self):
        if self.sample_file_static_data.pe:
            self.base_address = self.sample_file_static_data.pe.basic_info.image_base

    def _compute_exports(self):
        if self.sample_file_static_data.pe:
            for export in self.sample_file_static_data.pe.exports:
                self.exports[export.address] = export.api.name

    def _compute_imports(self):
        # TODO (meh)
        ...

    def _compute_sections(self):
        if self.sample_file_static_data.pe:
            for section in self.sample_file_static_data.pe.sections:
                self.sections[section.virtual_address] = section.name
