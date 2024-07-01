from typing import List
from pydantic import BaseModel

class Param(BaseModel):
    name: str
    type: str
    value: str

datatype = [
        "unknown", 
        "void", 
        "bool", 
        "signed_8bit", 
        "unsigned_8bit", 
        "signed_16bit", 
        "unsigned_16bit", 
        "signed_32bit", 
        "unsigned_32bit", 
        "signed_64bit", 
        "unsigned_64bit", 
        "double", 
        "void_ptr", 
        "ptr", 
        "str", 
        "array", 
        "container", 
        "bindata", 
        "undefined_type"

        ]

param_list = [
{"name": "LpLibFileName", "type": "ptr", "value": "0xc27b98"}, 
{"name": "DownloadDLL", "type": "double", "value": "0x12345"}, 
{"name": "MalicousDLL", "type": "unknown", "value": "0x928347"}

]

def is_valid_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False

# Converts "value"'s value from a hex string to a decimal int.

for param_data in param_list:
    if param_data['type'] in datatype:
        if is_valid_hex(param_data['value']):
            # Convert hexadecimal string to integer
            int_value = int(param_data['value'], 16)
            # Update the dictionary with the integer value formatted as hexadecimal string
            param_data['value'] = int_value  # Store the integer value
            print(f"Converted value to int for '{param_data['name']}': {hex(int_value)}")
        else:
            print(f"Value '{param_data['value']}' is not a valid hexadecimal for '{param_data['name']}'")
    else:
        print(f"Invalid type '{param_data['type']}' for '{param_data['name']}'")

print(param_list)