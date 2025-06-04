from typing import Union, Iterator
from pathlib import Path

from .models import FridaReport, Call
from capa.features.common import Feature, String, OS, Arch, Format
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


class FridaExtractor(DynamicFeatureExtractor):
    """
    Frida dynamic analysis feature extractor for Android applications.
    
    Processes JSON output from Frida instrumentation to extract behavioral features.
    """
    def __init__(self, report: FridaReport):
        super().__init__(
            hashes=SampleHashes(md5="", sha1="", sha256="")
        )
        self.report: FridaReport = report


    def get_base_address(self) -> Union[_NoAddress, None]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        """Basic global features"""
        yield OS("android"), NO_ADDRESS
        yield Arch("aarch64"), NO_ADDRESS 
        yield Format("android"), NO_ADDRESS

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        """Baisc file features"""
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
                addr = DynamicCallAddress(thread=th.address, id=i)
                yield CallHandle(address=addr, inner=call)

    def extract_call_features(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        """Extract features from individual API calls"""
        # TODO: Implement call feature extraction
        
    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        """Format API call name and parameters"""
        call: Call = ch.inner
        
        parts = []
        parts.append(call.api)
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
        return cls(report)