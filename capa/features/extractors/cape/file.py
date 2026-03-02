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
    get all the created processes for a sample.

    when the OS recycles a PID, multiple processes in the report may share the
    same (ppid, pid) pair.  we detect this and assign sequential ids so that
    each process receives a unique ProcessAddress.
    """
    # first pass: count how many times each (ppid, pid) pair appears
    counts: dict[tuple[int, int], int] = {}
    for process in report.behavior.processes:
        key = (process.parent_id, process.process_id)
        counts[key] = counts.get(key, 0) + 1

    # second pass: yield handles with sequential ids for reused pairs
    seq: dict[tuple[int, int], int] = {}
    for process in report.behavior.processes:
        key = (process.parent_id, process.process_id)
        seq[key] = seq.get(key, 0) + 1

        # only assign ids when reuse is detected; otherwise keep id=None
        # for backward compatibility with existing addresses and freeze files
        id_ = seq[key] if counts[key] > 1 else None
        if id_ is not None:
            logger.debug(
                "pid reuse detected for ppid=%d, pid=%d: assigning id=%d",
                process.parent_id,
                process.process_id,
                id_,
            )

        addr = ProcessAddress(pid=process.process_id, ppid=process.parent_id, id=id_)
        yield ProcessHandle(address=addr, inner=process)


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
    if not report.behavior.summary:
        return

    for regkey in report.behavior.summary.keys:
        yield String(regkey), NO_ADDRESS


def extract_used_files(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if not report.behavior.summary:
        return

    for file in report.behavior.summary.files:
        yield String(file), NO_ADDRESS


def extract_used_mutexes(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if not report.behavior.summary:
        return

    for mutex in report.behavior.summary.mutexes:
        yield String(mutex), NO_ADDRESS


def extract_used_commands(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if not report.behavior.summary:
        return

    for cmd in report.behavior.summary.executed_commands:
        yield String(cmd), NO_ADDRESS


def extract_used_apis(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if not report.behavior.summary:
        return

    for symbol in report.behavior.summary.resolved_apis:
        yield String(symbol), NO_ADDRESS


def extract_used_services(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if not report.behavior.summary:
        return

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
