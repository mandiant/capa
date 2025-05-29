import logging
from typing import Union, Iterator
from pathlib import Path

from .models import AndroidReport, Call
from capa.features.common import Feature
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

logger = logging.getLogger(__name__)


class AndroidFeatureExtractor(DynamicFeatureExtractor):
    
    def __init__(self, report: AndroidReport):
        # TODO: Not sure how to get APK hashes yet, will figure out later
        super().__init__(
            hashes=SampleHashes(md5="", sha1="", sha256="")
        )
        self.report: AndroidReport = report
        
        self.global_features = []

    def get_base_address(self) -> Union[_NoAddress, None]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        # TODO: Need to figure out what global features Android should have
        yield from self.global_features

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        # TODO: Will extract file-level features from Frida data later
        yield from []

    def get_processes(self) -> Iterator[ProcessHandle]:
        """Get all processes from the report"""
        for process in self.report.processes:
            addr = ProcessAddress(pid=process.pid, ppid=0)
            yield ProcessHandle(address=addr, inner=process)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        # TODO: Need to understand what process-level features make sense for Android
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
        # TODO: Need to understand what thread features would be useful for Android
        yield from []

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        """Get all API calls in a specific thread"""
        for i, call in enumerate(ph.inner.calls):
            if call.thread_id == th.address.tid:
                addr = DynamicCallAddress(thread=th.address, id=i)
                yield CallHandle(address=addr, inner=call)

    def extract_call_features(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        # TODO: Implement call feature extraction (not sure API names, arguments, return values)
        yield from []

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
        
        if call.return_value:
            parts.append(f" -> {call.return_value}")
            
        return "".join(parts)

    @classmethod
    def from_frida_log(cls, package_name: str, log_file: Path) -> "AndroidFeatureExtractor":
        """Create extractor from Frida log file - main entry point"""
        with open(log_file, 'r', encoding='utf-8') as f:
            log_lines = f.readlines()
            
        report = AndroidReport.from_frida_logs(package_name, log_lines)
        return cls(report)