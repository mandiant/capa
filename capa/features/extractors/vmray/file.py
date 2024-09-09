# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Dict, Tuple, Iterator

import capa.features.extractors.common
from capa.features.file import Export, Import, Section
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.vmray import VMRayAnalysis
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.vmray.models import Process
from capa.features.extractors.base_extractor import ProcessHandle

logger = logging.getLogger(__name__)


def get_processes(analysis: VMRayAnalysis) -> Iterator[ProcessHandle]:
    processes: Dict[str, Process] = analysis.sv2.processes

    for process in processes.values():
        # we map VMRay's monitor ID to the OS PID to make it easier for users
        # to follow the processes in capa's output
        pid: int = analysis.get_process_os_pid(process.monitor_id)
        ppid: int = (
            analysis.get_process_os_pid(processes[process.ref_parent_process.path[1]].monitor_id)
            if process.ref_parent_process
            else 0
        )

        addr: ProcessAddress = ProcessAddress(pid=pid, ppid=ppid)
        yield ProcessHandle(address=addr, inner=process)


def extract_export_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for addr, name in analysis.exports.items():
        yield Export(name), AbsoluteVirtualAddress(addr)


def extract_import_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for addr, (module, api) in analysis.imports.items():
        for symbol in generate_symbols(module, api, include_dll=True):
            yield Import(symbol), AbsoluteVirtualAddress(addr)


def extract_section_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for addr, name in analysis.sections.items():
        yield Section(name), AbsoluteVirtualAddress(addr)


def extract_referenced_filenames(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for filename in analysis.sv2.filenames.values():
        yield String(filename.filename), NO_ADDRESS


def extract_referenced_mutex_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for mutex in analysis.sv2.mutexes.values():
        yield String(mutex.name), NO_ADDRESS


def extract_referenced_domain_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for domain in analysis.sv2.domains.values():
        yield String(domain.domain), NO_ADDRESS


def extract_referenced_ip_addresses(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for ip_address in analysis.sv2.ip_addresses.values():
        yield String(ip_address.ip_address), NO_ADDRESS


def extract_referenced_registry_key_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for registry_record in analysis.sv2.registry_records.values():
        yield String(registry_record.reg_key_name), NO_ADDRESS


def extract_file_strings(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.common.extract_file_strings(analysis.sample_file_buf)


def extract_features(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(analysis):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    extract_referenced_filenames,
    extract_referenced_mutex_names,
    extract_referenced_domain_names,
    extract_referenced_ip_addresses,
    extract_referenced_registry_key_names,
    extract_file_strings,
)
