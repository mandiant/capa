from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict
import json


class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class Call(FlexibleModel):
    """Represents a single API call captured by Frida"""
    api_name: str           # API name like "java.io.File.<init>", not sure if need to seperate 'japi' 'napi' 'jni'...
    process_id: int
    thread_id: int 
    call_id: int                             
    
    # timestamp: Optional[str] = None
    # arguments: Dict[str, Any] = Field(default_factory=dict)
    # return_value: Optional[Any] = None     # Not very sure if we should use str as the return value type.
    # caller: Optional[str] = None


class Process(FlexibleModel):
    """Process information from Frida analysis"""
    # ppid不存储在这里，因为Android应用通常是单进程的，在extractor.py中处理时会设置ppid=0
    pid: int
    package_name: str
    arch: Optional[str] = None
    platform: Optional[str] = None
    calls: List[Call] = Field(default_factory=list)

class FridaReport(FlexibleModel):
    """Main report structure for Android analysis"""
    # TODO: Some more file-level information may go here.
    package_name: str
    processes: List[Process] = Field(default_factory=list)
    
    @classmethod
    def from_json_file(cls, json_path) -> "FridaReport":
        """Load from JSON Lines file created by log_converter.py"""
        metadata = None
        api_calls = []

        with open(json_path, 'r') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    
                    if "metadata" in record:
                        metadata = record["metadata"]
                    elif "api" in record and "java_api" in record["api"]:
                        api_calls.append(record["api"]["java_api"])

        process = Process(
            pid=metadata["process_id"],
            package_name=metadata.get("package_name"),
            arch=metadata.get("arch"),
            platform=metadata.get("platform"),
            calls=[Call(**call) for call in api_calls]
        )
        
        return cls(
            package_name=metadata.get("package_name"),
            processes=[process]
        )
    