from typing import Union, Iterator
from pathlib import Path

from capa.features.extractors.frida.models import FridaReport, Call
from capa.features.common import Feature, String, OS, Arch, Format, FORMAT_ANDROID
from capa.features.insn import API, Number
from capa.features.address import (
    NO_ADDRESS,
    Address,
    ThreadAddress,
    ProcessAddress,
    DynamicCallAddress,
    _NoAddress
)
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)
import logging

logger = logging.getLogger(__name__)

class FridaExtractor(DynamicFeatureExtractor):
    """
    Frida dynamic analysis feature extractor for Android applications.
    
    Processes JSON output from Frida instrumentation to extract behavioral features.
    """
    def __init__(self, report: FridaReport):
        # TODO: From what I’ve found, Frida cannot access original APK file to compute hashes at runtime.
        # we may need to require users to provide both the Frida-generated log file and original file to capa,
        # like we do with other extractors e.g. BinExport, VMRay, etc..
        super().__init__(
            hashes=SampleHashes(md5="", sha1="", sha256="")
        )
        self.report: FridaReport = report


    def get_base_address(self) -> Union[_NoAddress, None]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        """Basic global features"""
        yield OS("android"), NO_ADDRESS  # OS: Frida doesn't provide OS info

        if self.report.processes:
            process = self.report.processes[0]
            
            if process.arch:
                arch_mapping = {
                    "arm64": "aarch64",
                    "arm": "arm",
                    "x64": "amd64", 
                    "x86": "i386"
                }
                capa_arch = arch_mapping.get(process.arch, process.arch)
                yield Arch(capa_arch), NO_ADDRESS
            
            if process.platform:
                # TODO: capa doesn't have a dedicated FORMAT_ANDROID constant yet.
                yield Format(FORMAT_ANDROID), NO_ADDRESS
        
    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        """Basic file features"""
        yield String(self.report.package_name), NO_ADDRESS

    def get_processes(self) -> Iterator[ProcessHandle]:
        """Get all processes from the report"""
        for process in self.report.processes:
            addr = ProcessAddress(pid=process.pid, ppid=0)
            yield ProcessHandle(address=addr, inner=process)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        # TODO: we have not identified process-specific features for Frida yet
        yield from []

    def get_process_name(self, ph: ProcessHandle) -> str:
        return ph.inner.package_name

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        """Get all threads by grouping calls by thread_id"""
        thread_ids = set()
        for call in ph.inner.calls:
            thread_ids.add(call.thread_id)

        for tid in thread_ids:
            addr = ThreadAddress(process=ph.address, tid=tid)
            yield ThreadHandle(address=addr, inner={"tid": tid})
            
    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[tuple[Feature, Address]]:
        # TODO: we have not identified thread-specific features for Frida yet
        yield from []

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        """Get all API calls in a specific thread"""
        for i, call in enumerate(ph.inner.calls):
            if call.thread_id == th.address.tid:
                addr = DynamicCallAddress(thread=th.address, id=call.call_id)
                yield CallHandle(address=addr, inner=call)

    def extract_call_features(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        """Extract features from individual API calls"""
        # TODO: Implement call feature extraction from arguments and return value
        call: Call = ch.inner

        yield API(call.api_name), ch.address

    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        """Format API call name and parameters"""
        # TODO: Implement after extract_call_features agruments
        call: Call = ch.inner
        
        parts = []
        parts.append(call.api_name)
        parts.append("(")
        
        if call.arguments:
            args = [f"{k}={v}" for k, v in call.arguments.items()]
            parts.append(", ".join(args))
        
        parts.append(")")
            
        return "".join(parts)
    
    @classmethod
    def from_json_file(cls, json_path: Path) -> "FridaExtractor":
        """Entry point: Create an extractor from a JSON file""" 
        report = FridaReport.from_json_file(json_path)
        logger.info(f"Successfully loaded report with {len(report.processes)} processes")
        return cls(report)