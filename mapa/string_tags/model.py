from __future__ import annotations

from dataclasses import field, dataclass


@dataclass
class StringTagMatch:
    tag: str
    source_family: str
    source_name: str
    kind: str = ""
    library_name: str = ""
    library_version: str = ""
    file_path: str = ""
    function_name: str = ""
    line_number: int | None = None
    note: str = ""
    description: str = ""
    action: str = ""
    global_count: int | None = None
    encoding: str = ""
    location: str = ""

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        return (self.tag, self.source_family, self.source_name, self.library_name, self.note, self.kind)


@dataclass
class StringTagResult:
    tags: tuple[str, ...]
    matches: tuple[StringTagMatch, ...] = field(default_factory=tuple)

    @classmethod
    def empty(cls) -> StringTagResult:
        return cls(tags=(), matches=())
