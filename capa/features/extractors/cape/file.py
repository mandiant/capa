# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
from typing import Iterator

from capa.features.file import Export, Import, Section
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.cape.models import CapeReport
from capa.features.extractors.base_extractor import ProcessHandle

logger = logging.getLogger(__name__)


def get_processes(report: CapeReport) -> Iterator[ProcessHandle]:
    """
    get all the created processes for a sample
    """
    seen_processes = {}
    for process in report.behavior.processes:
        addr = ProcessAddress(pid=process.process_id, ppid=process.parent_id)
        yield ProcessHandle(address=addr, inner=process)

        # check for pid and ppid reuse
        if addr not in seen_processes:
            seen_processes[addr] = [process]
        else:
            logger.warning(
                "pid and ppid reuse detected between process %s and process%s: %s",
                process,
                "es" if len(seen_processes[addr]) > 1 else "",
                seen_processes[addr],
            )
            seen_processes[addr].append(process)


def extract_import_names(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    """
    extract imported function names
    """
    assert report.static is not None and report.static.pe is not None
    imports = report.static.pe.imports

    if isinstance(imports, dict):
        imports = list(imports.values())

    assert isinstance(imports, list)

    for library in imports:
        for function in library.imports:
            if not function.name:
                continue

            for name in generate_symbols(library.dll, function.name, include_dll=True):
                yield Import(name), AbsoluteVirtualAddress(function.address)


def extract_export_names(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    assert report.static is not None and report.static.pe is not None
    for function in report.static.pe.exports:
        yield Export(function.name), AbsoluteVirtualAddress(function.address)


def extract_section_names(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    assert report.static is not None and report.static.pe is not None
    for section in report.static.pe.sections:
        yield Section(section.name), AbsoluteVirtualAddress(section.virtual_address)


def extract_file_strings(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if report.strings is not None:
        for string in report.strings:
            yield String(string), NO_ADDRESS


def extract_used_regkeys(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for regkey in report.behavior.summary.keys:
        yield String(regkey), NO_ADDRESS


def extract_used_files(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for file in report.behavior.summary.files:
        yield String(file), NO_ADDRESS


def extract_used_mutexes(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for mutex in report.behavior.summary.mutexes:
        yield String(mutex), NO_ADDRESS


def extract_used_commands(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for cmd in report.behavior.summary.executed_commands:
        yield String(cmd), NO_ADDRESS


def extract_used_apis(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for symbol in report.behavior.summary.resolved_apis:
        yield String(symbol), NO_ADDRESS


def extract_used_services(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for svc in report.behavior.summary.created_services:
        yield String(svc), NO_ADDRESS
    for svc in report.behavior.summary.started_services:
        yield String(svc), NO_ADDRESS


def extract_features(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(report):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    extract_file_strings,
    extract_used_regkeys,
    extract_used_files,
    extract_used_mutexes,
    extract_used_commands,
    extract_used_apis,
    extract_used_services,
)
