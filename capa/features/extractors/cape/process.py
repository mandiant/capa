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

from capa.features.address import Address, ThreadAddress
from capa.features.common import Feature, String
from capa.features.extractors.base_extractor import ProcessHandle, ThreadHandle
from capa.features.extractors.cape.models import Process

logger = logging.getLogger(__name__)


def get_threads(ph: ProcessHandle) -> Iterator[ThreadHandle]:
    """
    get the threads associated with a given process
    """
    process: Process = ph.inner
    threads: list[int] = process.threads

    counts: dict[int, int] = {}
    for tid in threads:
        counts[tid] = counts.get(tid, 0) + 1

    seq: dict[int, int] = {}
    warned_tids: set[int] = set()
    for tid in threads:
        if counts[tid] > 1 and tid not in warned_tids:
            logger.warning("tid reuse detected for tid %d in process %s", tid, ph.address)
            warned_tids.add(tid)

        seq[tid] = seq.get(tid, 0) + 1
        thread_id = seq[tid] - 1 if counts[tid] > 1 else None

        address: ThreadAddress = ThreadAddress(process=ph.address, tid=tid, id=thread_id)
        yield ThreadHandle(address=address, inner={})


def extract_environ_strings(ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
    """
    extract strings from a process' provided environment variables.
    """
    process: Process = ph.inner

    for value in (value for value in process.environ.values() if value):
        yield String(value), ph.address


def extract_features(ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
    for handler in PROCESS_HANDLERS:
        for feature, addr in handler(ph):
            yield feature, addr


PROCESS_HANDLERS = (extract_environ_strings,)
