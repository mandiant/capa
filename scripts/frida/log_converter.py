""""
Frida Log Converter Tool

Convert Frida raw logs to standard JSON format for capa analysis

Usage:
    python3 log_converter.py <frida_log> <package_name> [output.json]
"""

import json
import sys
from pathlib import Path


def convert_frida_log_to_json(log_file: Path, package_name: str, output_file: Path = None) -> Path:
    """
    Convert Frida log to standard JSON format
    
    Returns: output file path
    """
    api_calls = []
    
    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if 'FRIDA_JSON:' in line:
                json_start = line.find('FRIDA_JSON:') + 11
                json_str = line[json_start:].strip()
                data = json.loads(json_str)
                
                if data.get("type") == "api":
                    call = {
                        "api": data["name"],
                        "arguments": data.get("args", {}),
                        "caller": data.get("method", "unknown"),
                        "timestamp": data.get("timestamp"),
                        "thread_id": data.get("thread_id", 0), 
                        "return_value": data.get("return_value")
                    }
                    api_calls.append(call)
                        
    
    capa_json = {
        "package_name": package_name,
        "processes": [  
            {
                "pid": 1,  # Default pid
                "package_name": package_name,
                "calls": api_calls
            }
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(capa_json, f, indent=2)
    
    return output_file


def main():
    if len(sys.argv) < 3:
        print("Frida Log Converter Tool")
        print("Usage: python log_converter.py <frida_log> <package_name> [output.json]")
        return
    
    log_file = Path(sys.argv[1])
    package_name = sys.argv[2]
    output_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    
    convert_frida_log_to_json(log_file, package_name, output_file)
    print("Done!")


if __name__ == "__main__":
    main()