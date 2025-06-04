from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict
import json


class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class Call(FlexibleModel):
    """Represents a single API call captured by Frida"""
    api: str           # API name like "java.io.File.<init>", not sure if need to seperate 'japi' 'napi' 'jni'...
    thread_id: int                             
    timestamp: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    return_value: Optional[str] = None
    caller: Optional[str] = None


class Process(FlexibleModel):
    """Process information from Frida analysis"""
    pid: int
    package_name: str
    calls: List[Call] = Field(default_factory=list)


class FridaReport(FlexibleModel):
    """Main report structure for Android analysis"""
    package_name: str
    processes: List[Process] = Field(default_factory=list)
    
    @classmethod
    def from_json_file(cls, json_path) -> "FridaReport":
        """Load from JSON file created by log_converter.py"""
        with open(json_path, 'r') as f:
            data = json.load(f)
        return cls.model_validate(data) #
    