# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, List, Union, Literal, Optional

# TODO install/force lxml?
from pydantic_xml import BaseXmlModel, attr, element


class FunctionCall(BaseXmlModel, tag="fncall"):
    # ts: str = attr()
    # fncall_id: int = attr()
    # process_id: int = attr()
    name: str = attr()
    # in_: element(name="in")
    # out: element()


class MonitorProcess(BaseXmlModel, tag="monitor_process"):
    ts: str = attr()
    process_id: int = attr()
    image_name: str = attr()


class MonitorThread(BaseXmlModel, tag="monitor_thread"):
    ts: str = attr()
    thread_id: int = attr()
    process_id: int = attr()
    os_tid: str = attr()  # TODO hex


class Analysis(BaseXmlModel, tag="analysis"):
    log_version: str = attr()
    analyzer_version: str = attr()
    analysis_date: str = attr()
    processes: List[MonitorProcess] = element(tag="monitor_process")
    threads: List[MonitorThread] = element(tag="monitor_thread")
    # failing so far...
    # fncall: List[FunctionCall] = element(tag="fncall")
