# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import json
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from zipfile import ZipFile
from collections import defaultdict

import xmltodict

from capa.exceptions import UnsupportedFormatError
from capa.features.extractors.vmray.models import File, Flog, SummaryV2, StaticData, FunctionCall

logger = logging.getLogger(__name__)

# TODO (meh): is default password "infected" good enough?? https://github.com/mandiant/capa/issues/2148
DEFAULT_ARCHIVE_PASSWORD = b"infected"

SUPPORTED_FLOG_VERSIONS = ("2",)


class VMRayAnalysis:
    def __init__(self, zipfile_path: Path):
        self.zipfile = ZipFile(zipfile_path, "r")

        # summary_v2.json is the entry point to the entire VMRay archive and
        # we use its data to find everything else that we need for capa
        sv2_json = json.loads(self.zipfile.read("logs/summary_v2.json", pwd=DEFAULT_ARCHIVE_PASSWORD))
        self.sv2 = SummaryV2.model_validate(sv2_json)
        self.file_type: str = self.sv2.analysis_metadata.sample_type

        # flog.xml contains all of the call information that VMRay captured during execution
        flog_xml = self.zipfile.read("logs/flog.xml", pwd=DEFAULT_ARCHIVE_PASSWORD)
        flog_json = xmltodict.parse(flog_xml, attr_prefix="")
        self.flog = Flog.model_validate(flog_json)

        if self.flog.analysis.log_version not in SUPPORTED_FLOG_VERSIONS:
            logger.warning("VMRay feature extractor does not support flog version %s", self.flog.analysis.log_version)
            raise UnsupportedFormatError(
                "VMRay feature extractor does not support flog version %s", self.flog.analysis.log_version
            )

        self.exports: Dict[int, str] = {}
        self.imports: Dict[int, Tuple[str, str]] = {}
        self.sections: Dict[int, str] = {}
        self.process_ids: Dict[int, int] = {}
        self.process_threads: Dict[int, List[int]] = defaultdict(list)
        self.process_calls: Dict[int, Dict[int, List[FunctionCall]]] = defaultdict(lambda: defaultdict(list))
        self.base_address: int

        self.sample_file_name: Optional[str] = None
        self.sample_file_analysis: Optional[File] = None
        self.sample_file_static_data: Optional[StaticData] = None

        self._find_sample_file()

        if self.sample_file_name is None or self.sample_file_analysis is None:
            logger.warning("VMRay archive does not contain sample file (file_type: %s)", self.file_type)
            raise UnsupportedFormatError("VMRay archive does not contain sample file (file_type: %s)", self.file_type)

        if not self.sample_file_static_data:
            logger.warning("VMRay archive does not contain static data (file_type: %s)", self.file_type)
            raise UnsupportedFormatError("VMRay archive does not contain static data (file_type: %s)", self.file_type)

        if not self.sample_file_static_data.pe:
            logger.warning("VMRay feature extractor only supports PE at this time (file_type: %s)", self.file_type)
            raise UnsupportedFormatError(
                "VMRay feature extractor only supports PE at this time(file_type: %s)", self.file_type
            )

        # VMRay does not store static strings for the sample file so we must use the source file
        # stored in the archive
        sample_sha256: str = self.sample_file_analysis.hash_values.sha256.lower()
        sample_file_path: str = f"internal/static_analyses/{sample_sha256}/objects/files/{sample_sha256}"

        logger.debug("file_type: %s, file_path: %s", self.file_type, sample_file_path)

        self.sample_file_buf: bytes = self.zipfile.read(sample_file_path, pwd=DEFAULT_ARCHIVE_PASSWORD)

        # only compute these if we've found a supported sample file type
        self._compute_base_address()
        self._compute_imports()
        self._compute_exports()
        self._compute_sections()
        self._compute_process_ids()
        self._compute_process_threads()
        self._compute_process_calls()

    def _find_sample_file(self):
        for file_name, file_analysis in self.sv2.files.items():
            if file_analysis.is_sample:
                # target the sample submitted for analysis
                self.sample_file_name = file_name
                self.sample_file_analysis = file_analysis

                if file_analysis.ref_static_data:
                    self.sample_file_static_data = self.sv2.static_data[file_analysis.ref_static_data.path[1]]

                break

    def _compute_base_address(self):
        assert self.sample_file_static_data is not None
        if self.sample_file_static_data.pe:
            self.base_address = self.sample_file_static_data.pe.basic_info.image_base

    def _compute_exports(self):
        assert self.sample_file_static_data is not None
        if self.sample_file_static_data.pe:
            for export in self.sample_file_static_data.pe.exports:
                self.exports[export.address] = export.api.name

    def _compute_imports(self):
        assert self.sample_file_static_data is not None
        if self.sample_file_static_data.pe:
            for module in self.sample_file_static_data.pe.imports:
                for api in module.apis:
                    self.imports[api.address] = (module.dll, api.api.name)

    def _compute_sections(self):
        assert self.sample_file_static_data is not None
        if self.sample_file_static_data.pe:
            for section in self.sample_file_static_data.pe.sections:
                self.sections[section.virtual_address] = section.name

    def _compute_process_ids(self):
        for process in self.sv2.processes.values():
            # we expect VMRay's monitor IDs to be unique, but OS PIDs may be reused
            assert process.monitor_id not in self.process_ids.keys()
            self.process_ids[process.monitor_id] = process.os_pid

    def _compute_process_threads(self):
        # logs/flog.xml appears to be the only file that contains thread-related data
        # so we use it here to map processes to threads
        for function_call in self.flog.analysis.function_calls:
            pid: int = self.get_process_os_pid(function_call.process_id)  # flog.xml uses process monitor ID, not OS PID
            tid: int = function_call.thread_id

            assert isinstance(pid, int)
            assert isinstance(tid, int)

            if tid not in self.process_threads[pid]:
                self.process_threads[pid].append(tid)

    def _compute_process_calls(self):
        for function_call in self.flog.analysis.function_calls:
            pid: int = self.get_process_os_pid(function_call.process_id)  # flog.xml uses process monitor ID, not OS PID
            tid: int = function_call.thread_id

            assert isinstance(pid, int)
            assert isinstance(tid, int)

            self.process_calls[pid][tid].append(function_call)

    def get_process_os_pid(self, monitor_id: int) -> int:
        return self.process_ids[monitor_id]
