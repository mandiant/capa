from __future__ import annotations

import json
from typing import Any
from dataclasses import field, dataclass


@dataclass
class AssemblageLocation:
    name: str
    file: str
    prototype: str
    rva: int

    @property
    def path(self) -> str:
        if not self.file.endswith(")"):
            return self.file
        return self.file.rpartition(" (")[0]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssemblageLocation:
        return cls(
            name=data["name"],
            file=data["file"],
            prototype=data["prototype"],
            rva=data["function_start"],
        )

    @classmethod
    def from_json(cls, doc: str) -> AssemblageLocation:
        return cls.from_dict(json.loads(doc))


@dataclass
class MapaString:
    value: str
    address: int


@dataclass
class MapaCall:
    name: str
    address: int
    is_api: bool
    delta: int = 0
    direction: str = ""


@dataclass
class MapaCaller:
    name: str
    address: int
    delta: int = 0
    direction: str = ""


@dataclass
class MapaFunction:
    address: int
    name: str
    is_thunk: bool = False
    is_library: bool = False
    num_basic_blocks: int = 0
    num_edges: int = 0
    num_instructions: int = 0
    total_instruction_bytes: int = 0
    callers: list[MapaCaller] = field(default_factory=list)
    calls: list[MapaCall] = field(default_factory=list)
    apis: list[MapaCall] = field(default_factory=list)
    strings: list[MapaString] = field(default_factory=list)
    capa_matches: list[str] = field(default_factory=list)


@dataclass
class MapaSection:
    address: int
    size: int
    perms: str
    name: str = ""


@dataclass
class MapaLibrary:
    name: str
    is_static: bool = False
    load_address: int | None = None


@dataclass
class MapaMeta:
    name: str
    sha256: str
    md5: str = ""
    arch: str = ""
    timestamp: str = ""
    base_address: int = 0


@dataclass
class MapaReport:
    meta: MapaMeta
    sections: list[MapaSection] = field(default_factory=list)
    libraries: list[MapaLibrary] = field(default_factory=list)
    functions: list[MapaFunction] = field(default_factory=list)
    assemblage_locations: dict[int, AssemblageLocation] = field(default_factory=dict)
