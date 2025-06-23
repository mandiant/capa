from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict
import json


class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class Metadata(FlexibleModel):
    process_id: int
    package_name: Optional[str] = None
    arch: Optional[str] = None
    platform: Optional[str] = None


class Argument(FlexibleModel):
    """Represents a single argument in an API call"""
    name: str
    value: Any


class Call(FlexibleModel):
    """Represents a single API call captured by Frida"""
    api_name: str           # API name like "java.io.File.<init>", not sure if need to seperate 'japi' 'napi' 'jni'...
    process_id: int
    thread_id: int 
    call_id: int                             
    # timestamp: Optional[str] = None
    arguments: List[Argument] = Field(default_factory=list)
    # return_value: Optional[Any] = None     # Not very sure if we should use str as the return value type
    # caller: Optional[str] = None


class Process(FlexibleModel):
    """Process information from Frida analysis"""
    # ppid is omitted here as Android apps are usually single-process; it will be set to 0 in extractor.py
    pid: int
    package_name: str
    arch: Optional[str] = None
    platform: Optional[str] = None
    calls: List[Call] = Field(default_factory=list)

class FridaReport(FlexibleModel):
    """Main report structure for Android analysis"""
    # TODO: Some more file-level information may go here
    package_name: str
    processes: List[Process] = Field(default_factory=list)
    
    @classmethod
    def from_json_file(cls, json_path) -> "FridaReport":
        """Load from JSON Lines file created by log_converter.py"""
        metadata = None
        api_calls = []

        with open(json_path, 'r') as f:
            content = f.read()
            for line in content.splitlines():
                record = json.loads(line)
                
                if "metadata" in record:
                    metadata = Metadata(**record["metadata"])
                elif "api" in record and "java_api" in record["api"]:
                    call = Call(**record["api"]["java_api"])
                    api_calls.append(call)

        if not metadata:
            from capa.exceptions import UnsupportedFormatError
            raise UnsupportedFormatError("No metadata found in Frida report")

        if not api_calls:
            from capa.exceptions import EmptyReportError 
            raise EmptyReportError("No API calls found in Frida report")

        process = Process(
            pid=metadata.process_id,
            package_name=metadata.package_name,
            arch=metadata.arch,
            platform=metadata.platform,
            calls=api_calls
        )
        
        return cls(
            package_name=metadata.package_name,
            processes=[process]
        )
    