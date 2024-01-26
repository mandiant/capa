# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, Tuple, Union, Iterator

import capa.features.extractors.cape.call
import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
from capa.exceptions import EmptyReportError, UnsupportedFormatError
from capa.features.common import Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, _NoAddress
from capa.features.extractors.cape.models import Call, Static, Process, CapeReport
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)

logger = logging.getLogger(__name__)

TESTED_VERSIONS = {"2.2-CAPE", "2.4-CAPE"}


class CapeExtractor(DynamicFeatureExtractor):
    def __init__(self, report: CapeReport):
        super().__init__(
            hashes=SampleHashes(
                md5=report.target.file.md5.lower(),
                sha1=report.target.file.sha1.lower(),
                sha256=report.target.file.sha256.lower(),
            )
        )
        self.report: CapeReport = report

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = list(capa.features.extractors.cape.global_.extract_features(self.report))

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, _NoAddress, None]:
        # value according to the PE header, the actual trace may use a different imagebase
        assert self.report.static is not None and self.report.static.pe is not None
        return AbsoluteVirtualAddress(self.report.static.pe.imagebase)

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.file.extract_features(self.report)

    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.cape.file.get_processes(self.report)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.process.extract_features(ph)

    def get_process_name(self, ph) -> str:
        process: Process = ph.inner
        return process.process_name

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        yield from capa.features.extractors.cape.process.get_threads(ph)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
        if False:
            # force this routine to be a generator,
            # but we don't actually have any elements to generate.
            yield Characteristic("never"), NO_ADDRESS
        return

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        yield from capa.features.extractors.cape.thread.get_calls(ph, th)

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.call.extract_features(ph, th, ch)

    def get_call_name(self, ph, th, ch) -> str:
        call: Call = ch.inner

        parts = []
        parts.append(call.api)
        parts.append("(")
        for argument in call.arguments:
            parts.append(argument.name)
            parts.append("=")

            if argument.pretty_value:
                parts.append(argument.pretty_value)
            else:
                if isinstance(argument.value, int):
                    parts.append(hex(argument.value))
                elif isinstance(argument.value, str):
                    parts.append('"')
                    parts.append(argument.value)
                    parts.append('"')
                elif isinstance(argument.value, list):
                    pass
                else:
                    capa.helpers.assert_never(argument.value)

            parts.append(", ")
        if call.arguments:
            # remove the trailing comma
            parts.pop()
        parts.append(")")
        parts.append(" -> ")
        if call.pretty_return:
            parts.append(call.pretty_return)
        else:
            parts.append(hex(call.return_))

        return "".join(parts)

    @classmethod
    def from_report(cls, report: Dict) -> "CapeExtractor":
        cr = CapeReport.model_validate(report)

        if cr.info.version not in TESTED_VERSIONS:
            logger.warning("CAPE version '%s' not tested/supported yet", cr.info.version)

        # TODO(mr-tz): support more file types
        # https://github.com/mandiant/capa/issues/1933
        if "PE" not in cr.target.file.type:
            logger.error(
                "capa currently only supports PE target files, this target file's type is: '%s'.\nPlease report this at: https://github.com/mandiant/capa/issues/1933",
                cr.target.file.type,
            )

        # observed in 2.4-CAPE reports from capesandbox.com
        if cr.static is None and cr.target.file.pe is not None:
            cr.static = Static()
            cr.static.pe = cr.target.file.pe

        if cr.static is None:
            raise UnsupportedFormatError("CAPE report missing static analysis")

        if cr.static.pe is None:
            raise UnsupportedFormatError("CAPE report missing PE analysis")

        if len(cr.behavior.processes) == 0:
            raise EmptyReportError("CAPE did not capture any processes")

        return cls(cr)
