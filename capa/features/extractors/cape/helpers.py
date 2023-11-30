# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, List

from capa.features.extractors.base_extractor import ProcessHandle


def find_process(processes: List[Dict[str, Any]], ph: ProcessHandle) -> Dict[str, Any]:
    """
    find a specific process identified by a process handler.

    args:
      processes: a list of processes extracted by CAPE
      ph: handle of the sought process

    return:
      a CAPE-defined dictionary for the sought process' information
    """

    for process in processes:
        if ph.address.ppid == process["parent_id"] and ph.address.pid == process["process_id"]:
            return process
    return {}
