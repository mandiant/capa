from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FlexibleModel(BaseModel):
    """Base model that allows extra fields"""
    class Config:
        extra = "allow"


class Call(FlexibleModel):
    """Represents a single API call captured by Frida"""
    api: str           # API name like "java.io.File.<init>", not sure if need to seperate 'japi' 'napi' 'jni'...
    thread_id: int                             
    timestamp: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    return_value: Optional[str] = None
    caller: Optional[str] = None


class Process(FlexibleModel):
    """Android process information"""
    pid: int
    package_name: str
    calls: List[Call] = Field(default_factory=list)


class AndroidReport(FlexibleModel):
    """Main report structure for Android analysis"""
    package_name: str
    processes: List[Process] = Field(default_factory=list)
    
    @classmethod
    def from_frida_logs(cls, package_name: str, log_lines: List[str]) -> "AndroidReport":
        """Parse Frida JSON logs into structured report"""
        import json
        
        report = cls(package_name=package_name)
        
        # TODO: Create a single process for now (maybe I can extend later)
        process = Process(pid=1, package_name=package_name)
        
        for line in log_lines:
            if "{" in line and "}" in line:
                try:
                    # Extract JSON from Frida log line
                    start = line.find("{")
                    end = line.rfind("}") + 1
                    json_str = line[start:end]
                    data = json.loads(json_str)
                    
                    if data.get("type") == "api":
                        call = Call(
                            api=data["name"],
                            thread_id=data.get("thread_id", 0),
                            arguments=data.get("args", {}),
                            caller=data.get("method", "unknown")
                        )
                        process.calls.append(call)
                        
                except json.JSONDecodeError:
                    continue
                    
        report.processes.append(process)
        return report