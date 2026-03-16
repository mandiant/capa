from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AssemblageRecord:
    sha256: str
    name: str
    start_rva: int
    end_rva: int
    address: int
    end_address: int
    source_file: str

    @property
    def source_path(self) -> str:
        if not self.source_file.endswith(")"):
            return self.source_file
        head, separator, _ = self.source_file.rpartition(" (")
        if separator:
            return head
        return self.source_file

    @classmethod
    def from_csv_row(
        cls, row: Mapping[str, str], base_address: int
    ) -> AssemblageRecord:
        start_rva = int(row["start"], 0)
        end_rva = int(row["end"], 0)
        return cls(
            sha256=row["hash"].strip().lower(),
            name=row["name"].strip(),
            start_rva=start_rva,
            end_rva=end_rva,
            address=base_address + start_rva,
            end_address=base_address + end_rva,
            source_file=row["source_file"].strip(),
        )


@dataclass
class MapaString:
    value: str
    address: int
    tags: tuple[str, ...] = ()
    tag_matches: tuple = ()


@dataclass
class MapaProgramString:
    value: str
    address: int
    tags: tuple[str, ...] = ()
    tag_matches: tuple = ()
    function_addresses: tuple[int, ...] = ()


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
    assemblage_records: list[AssemblageRecord] = field(default_factory=list)


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
    program_strings: list[MapaProgramString] = field(default_factory=list)
