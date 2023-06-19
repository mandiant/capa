# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Any, Dict, List, Tuple, Iterator

import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle, DynamicExtractor

logger = logging.getLogger(__name__)


def get_processes(behavior: Dict) -> Iterator[ProcessHandle]:
    """
    get all created processes for a sample
    """
    for process in behavior["processes"]:
        inner: Dict[str, str] = {"name": process["name"], "ppid": process["parent_id"]}
        yield ProcessHandle(pid=process["process_id"], inner=inner)


def get_threads(behavior: Dict, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    get a thread's child processes
    """

    threads: List = None
    for process in behavior["processes"]:
        if ph.pid == process["process_id"] and ph.inner["ppid"] == process["parent_id"]:
            threads = process["threads"]

    for thread in threads:
        yield ThreadHandle(int(thread))


def extract_environ_strings(behavior: Dict, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract strings from a process' provided environment variables.
    """
    environ: Dict[str, str] = None
    for process in behavior["processes"]:
        if ph.pid == process["process_id"] and ph.inner["ppid"] == process["parent_id"]:
            environ = process["environ"]

    if not environ:
        return

    for variable, value in environ.items():
        if value:
            yield String(value), NO_ADDRESS


def extract_features(behavior: Dict, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in PROCESS_HANDLERS:
        for feature, addr in handler(behavior, ph):
            yield feature, addr


PROCESS_HANDLERS = (extract_environ_strings,)
