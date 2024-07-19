# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import itertools
from typing import Dict, List

from capa.features.address import ThreadAddress, ProcessAddress
from capa.features.extractors.drakvuf.models import Call, DrakvufReport


def index_calls(report: DrakvufReport) -> Dict[ProcessAddress, Dict[ThreadAddress, List[Call]]]:
    # this method organizes calls into processes and threads, and then sorts them based on
    # timestamp so that we can address individual calls per index (CallAddress requires call index)
    result: Dict[ProcessAddress, Dict[ThreadAddress, List[Call]]] = {}
    for call in itertools.chain(report.syscalls, report.apicalls):
        if call.pid == 0:
            # DRAKVUF captures api/native calls from all processes running on the system.
            # we ignore the pid 0 since it's a system process and it's unlikely for it to
            # be hijacked or so on, in addition to capa addresses not supporting null pids
            continue
        proc_addr = ProcessAddress(pid=call.pid, ppid=call.ppid)
        thread_addr = ThreadAddress(process=proc_addr, tid=call.tid)
        if proc_addr not in result:
            result[proc_addr] = {}
        if thread_addr not in result[proc_addr]:
            result[proc_addr][thread_addr] = []

        result[proc_addr][thread_addr].append(call)

    for proc, threads in result.items():
        for thread in threads:
            result[proc][thread].sort(key=lambda call: call.timestamp)

    return result
