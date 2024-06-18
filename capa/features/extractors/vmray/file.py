# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Dict, Tuple, Iterator

from capa.features.file import Export, Section
from capa.features.common import Feature
from capa.features.address import Address, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.vmray import VMRayAnalysis
from capa.features.extractors.vmray.models import Process
from capa.features.extractors.base_extractor import ProcessHandle

logger = logging.getLogger(__name__)


def get_processes(analysis: VMRayAnalysis) -> Iterator[ProcessHandle]:
    processes: Dict[str, Process] = analysis.sv2.processes

    for _, process in processes.items():
        pid = process.os_pid
        ppid = processes[process.ref_parent_process.path[1]].os_pid if process.ref_parent_process else 0

        addr = ProcessAddress(pid=pid, ppid=ppid)
        yield ProcessHandle(address=addr, inner=process)


def extract_export_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for addr, name in analysis.exports.items():
        yield Export(name), AbsoluteVirtualAddress(addr)


def extract_import_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    # TODO (meh)
    yield from []


def extract_section_names(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for addr, name in analysis.sections.items():
        yield Section(name), AbsoluteVirtualAddress(addr)


def extract_features(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(analysis):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    # extract_file_strings,
)
