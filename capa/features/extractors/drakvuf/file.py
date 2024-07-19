# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, List, Tuple, Iterator

from capa.features.file import Import
from capa.features.common import Feature
from capa.features.address import Address, ThreadAddress, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.base_extractor import ProcessHandle
from capa.features.extractors.drakvuf.models import Call, DrakvufReport

logger = logging.getLogger(__name__)


def get_processes(calls: Dict[ProcessAddress, Dict[ThreadAddress, List[Call]]]) -> Iterator[ProcessHandle]:
    """
    Get all the created processes for a sample.
    """
    for proc_addr, calls_per_thread in calls.items():
        sample_call = next(iter(calls_per_thread.values()))[0]  # get process name
        yield ProcessHandle(proc_addr, inner={"process_name": sample_call.process_name})


def extract_import_names(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    """
    Extract imported function names.
    """
    if report.loaded_dlls is None:
        return
    dlls = report.loaded_dlls

    for dll in dlls:
        dll_base_name = dll.name.split("\\")[-1]
        for function_name, function_address in dll.imports.items():
            for name in generate_symbols(dll_base_name, function_name, include_dll=True):
                yield Import(name), AbsoluteVirtualAddress(function_address)


def extract_features(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(report):
            yield feature, addr


FILE_HANDLERS = (
    # TODO(yelhamer): extract more file features from other DRAKVUF plugins
    # https://github.com/mandiant/capa/issues/2169
    extract_import_names,
)
