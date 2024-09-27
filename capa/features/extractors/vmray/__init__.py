# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from zipfile import ZipFile
from collections import defaultdict
from dataclasses import dataclass

from capa.exceptions import UnsupportedFormatError
from capa.features.extractors.vmray.models import File, Flog, SummaryV2, StaticData, FunctionCall, xml_to_dict

logger = logging.getLogger(__name__)

DEFAULT_ARCHIVE_PASSWORD = b"infected"

SUPPORTED_FLOG_VERSIONS = ("2",)


@dataclass
class VMRayMonitorThread:
    tid: int  # thread ID assigned by OS
    monitor_id: int  # unique ID assigned to thread by VMRay
    process_monitor_id: int  # unqiue ID assigned to containing process by VMRay


@dataclass
class VMRayMonitorProcess:
    pid: int  # process ID assigned by OS
    ppid: int  # parent process ID assigned by OS
    monitor_id: int  # unique ID assigned to process by VMRay
    image_name: str


class VMRayAnalysis:
    def __init__(self, zipfile_path: Path):
        self.zipfile = ZipFile(zipfile_path, "r")

        # summary_v2.json is the entry point to the entire VMRay archive and
        # we use its data to find everything else that we need for capa
        self.sv2 = SummaryV2.model_validate_json(
            self.zipfile.read("logs/summary_v2.json", pwd=DEFAULT_ARCHIVE_PASSWORD)
        )
        self.file_type: str = self.sv2.analysis_metadata.sample_type

        # flog.xml contains all of the call information that VMRay captured during execution
        flog_xml = self.zipfile.read("logs/flog.xml", pwd=DEFAULT_ARCHIVE_PASSWORD)
        flog_dict = xml_to_dict(flog_xml)
        self.flog = Flog.model_validate(flog_dict)

        if self.flog.analysis.log_version not in SUPPORTED_FLOG_VERSIONS:
            raise UnsupportedFormatError(
                "VMRay feature extractor does not support flog version %s" % self.flog.analysis.log_version
            )

        self.exports: Dict[int, str] = {}
        self.imports: Dict[int, Tuple[str, str]] = {}
        self.sections: Dict[int, str] = {}
        self.monitor_processes: Dict[int, VMRayMonitorProcess] = {}
        self.monitor_threads: Dict[int, VMRayMonitorThread] = {}

        # map monitor thread IDs to their associated monitor process ID
        self.monitor_threads_by_monitor_process: Dict[int, List[int]] = defaultdict(list)

        # map function calls to their associated monitor thread ID mapped to its associated monitor process ID
        self.monitor_process_calls: Dict[int, Dict[int, List[FunctionCall]]] = defaultdict(lambda: defaultdict(list))

        self.base_address: int

        self.sample_file_name: Optional[str] = None
        self.sample_file_analysis: Optional[File] = None
        self.sample_file_static_data: Optional[StaticData] = None

        self._find_sample_file()

        # VMRay analysis archives in various shapes and sizes and file type does not definitively tell us what data
        # we can expect to find in the archive, so to be explicit we check for the various pieces that we need at
        # minimum to run capa analysis
        if self.sample_file_name is None or self.sample_file_analysis is None:
            raise UnsupportedFormatError("VMRay archive does not contain sample file (file_type: %s)" % self.file_type)

        if not self.sample_file_static_data:
            raise UnsupportedFormatError("VMRay archive does not contain static data (file_type: %s)" % self.file_type)

        if not self.sample_file_static_data.pe and not self.sample_file_static_data.elf:
            raise UnsupportedFormatError(
                "VMRay feature extractor only supports PE and ELF at this time (file_type: %s)" % self.file_type
            )

        # VMRay does not store static strings for the sample file so we must use the source file
        # stored in the archive
        sample_sha256: str = self.sample_file_analysis.hash_values.sha256.lower()
        sample_file_path: str = f"internal/static_analyses/{sample_sha256}/objects/files/{sample_sha256}"

        logger.debug("file_type: %s, file_path: %s", self.file_type, sample_file_path)

        self.sample_file_buf: bytes = self.zipfile.read(sample_file_path, pwd=DEFAULT_ARCHIVE_PASSWORD)

        # do not change order, it matters
        self._compute_base_address()
        self._compute_imports()
        self._compute_exports()
        self._compute_sections()
        self._compute_monitor_processes()
        self._compute_monitor_threads()
        self._compute_monitor_process_calls()

    def _find_sample_file(self):
        for file_name, file_analysis in self.sv2.files.items():
            if file_analysis.is_sample:
                # target the sample submitted for analysis
                self.sample_file_name = file_name
                self.sample_file_analysis = file_analysis

                if file_analysis.ref_static_data:
                    # like "path": ["static_data","static_data_0"] where "static_data_0" is the summary_v2 static data
                    # key for the file's static data
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
            for pefile_section in self.sample_file_static_data.pe.sections:
                self.sections[pefile_section.virtual_address] = pefile_section.name
        elif self.sample_file_static_data.elf:
            for elffile_section in self.sample_file_static_data.elf.sections:
                self.sections[elffile_section.header.sh_addr] = elffile_section.header.sh_name

    def _compute_monitor_processes(self):
        for process in self.sv2.processes.values():
            # we expect monitor IDs to be unique
            assert process.monitor_id not in self.monitor_processes

            ppid: int = (
                self.sv2.processes[process.ref_parent_process.path[1]].os_pid if process.ref_parent_process else 0
            )
            self.monitor_processes[process.monitor_id] = VMRayMonitorProcess(
                process.os_pid, ppid, process.monitor_id, process.image_name
            )

        # not all processes are recorded in SummaryV2.json, get missing data from flog.xml, see #2394
        for monitor_process in self.flog.analysis.monitor_processes:
            vmray_monitor_process: VMRayMonitorProcess = VMRayMonitorProcess(
                monitor_process.os_pid,
                monitor_process.os_parent_pid,
                monitor_process.process_id,
                monitor_process.image_name,
            )

            if monitor_process.process_id not in self.monitor_processes:
                self.monitor_processes[monitor_process.process_id] = vmray_monitor_process
            else:
                # we expect monitor processes recorded in both SummaryV2.json and flog.xml to equal
                assert self.monitor_processes[monitor_process.process_id] == vmray_monitor_process

    def _compute_monitor_threads(self):
        for monitor_thread in self.flog.analysis.monitor_threads:
            # we expect monitor IDs to be unique
            assert monitor_thread.thread_id not in self.monitor_threads

            self.monitor_threads[monitor_thread.thread_id] = VMRayMonitorThread(
                monitor_thread.os_tid, monitor_thread.thread_id, monitor_thread.process_id
            )

            # we expect each monitor thread ID to be unique for its associated monitor process ID e.g. monitor
            # thread ID 10 should not be captured twice for monitor process ID 1
            assert monitor_thread.thread_id not in self.monitor_threads_by_monitor_process[monitor_thread.thread_id]

            self.monitor_threads_by_monitor_process[monitor_thread.process_id].append(monitor_thread.thread_id)

    def _compute_monitor_process_calls(self):
        for function_call in self.flog.analysis.function_calls:
            self.monitor_process_calls[function_call.process_id][function_call.thread_id].append(function_call)
