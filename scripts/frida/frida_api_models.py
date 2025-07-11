from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator
import json
from pathlib import Path


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

    @model_validator(mode='after')
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


class JniApi(BaseModel):
    pass


class NativeApi(BaseModel):
    pass


class JavaSection(BaseModel):
    methods: List[JavaApi] = Field(default_factory=list)


class JniSection(BaseModel):
    methods: List[JniApi] = Field(default_factory=list)


class NativeSection(BaseModel):
    methods: List[NativeApi] = Field(default_factory=list)


class FridaApiSpec(BaseModel):
    """Main configuration for Frida APIs"""
    java: Optional[JavaSection] = None
    jni: Optional[JniSection] = None
    native: Optional[NativeSection] = None
    
    @classmethod
    def from_json_file(cls, json_path: Path) -> "FridaApiSpec":
        """Load and validate API configuration from JSON file"""
        with open(json_path, 'r') as f:
            data = json.load(f)
        return cls(**data)

