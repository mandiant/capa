import json
from typing import List, Optional
from pathlib import Path

from pydantic import Field, BaseModel, ConfigDict, model_validator


class JavaApi(BaseModel):
    package: str
    class_name: str = Field(alias="class")
    method: Optional[str] = None  # null only for constructors
    arguments: bool = True  # Whether to capture and log method arguments
    static: bool = False
    native: bool = False
    ctor: bool = False

    # Pydantic config, allowing using alias to visit field
    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def validate_java_api_field_consistency(self):
        if self.ctor:
            if self.method is not None:
                raise ValueError('Constructors must have "method" field as null.')
            if self.static:
                raise ValueError('Constructors must have "static" field as False.')
            if self.native:
                raise ValueError('Constructors must have "native" field as False.')
        else:
            if self.method is None:
                raise ValueError('Methods (ctor=false) "method" field cannot be null.')

        return self


SUPPORTED_NATIVE_TYPES = {"int", "uint", "bool", "char*", "const char*"}
UNSUPPORTED_NATIVE_TYPES = {"long", "ulong", "size_t", "float", "double", "void*", "pointer"}
VALID_NATIVE_TYPES = SUPPORTED_NATIVE_TYPES.union(UNSUPPORTED_NATIVE_TYPES)


class NativeApi(BaseModel):
    library: str
    function: str
    arguments: bool = True
    argument_types: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_argument_types(self):
        print(
            f"Reminder: supported types are {SUPPORTED_NATIVE_TYPES}. "
            f"If the API argument you added uses one of these types, make sure it is spelled correctly."
        )
        for arg_type in self.argument_types:
            if arg_type not in VALID_NATIVE_TYPES:
                print(f"Reminder: {arg_type}. Please double-check for typos.")
        return self


class JavaApis(BaseModel):
    methods: List[JavaApi] = Field(default_factory=list)


class NativeApis(BaseModel):
    methods: List[NativeApi] = Field(default_factory=list)


class FridaApiSpec(BaseModel):
    """Main configuration for Frida APIs"""

    java: Optional[JavaApis] = None
    native: Optional[NativeApis] = None

    @classmethod
    def from_json_file(cls, json_path: Path) -> "FridaApiSpec":
        """Load and validate API configuration from JSON file"""
        with open(json_path, "r") as f:
            data = json.load(f)
        return cls(**data)
