import gzip
import pathlib
from typing import Dict, Sequence
from dataclasses import dataclass

import msgspec


class LibraryString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str | None = None
    function_name: str | None = None
    line_number: int | None = None


@dataclass
class LibraryStringDatabase:
    metadata_by_string: Dict[str, LibraryString]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "LibraryStringDatabase":
        metadata_by_string: Dict[str, LibraryString] = {}
        decoder = msgspec.json.Decoder(type=LibraryString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)


DEFAULT_FILENAMES = (
    "brotli.jsonl.gz",
    "bzip2.jsonl.gz",
    "cryptopp.jsonl.gz",
    "curl.jsonl.gz",
    "detours.jsonl.gz",
    "jemalloc.jsonl.gz",
    "jsoncpp.jsonl.gz",
    "kcp.jsonl.gz",
    "liblzma.jsonl.gz",
    "libsodium.jsonl.gz",
    "libpcap.jsonl.gz",
    "mbedtls.jsonl.gz",
    "openssl.jsonl.gz",
    "sqlite3.jsonl.gz",
    "tomcrypt.jsonl.gz",
    "wolfssl.jsonl.gz",
    "zlib.jsonl.gz",
)

DEFAULT_PATHS = tuple(
    pathlib.Path(__file__).parent / "data" / "oss" / filename for filename in DEFAULT_FILENAMES
) + (pathlib.Path(__file__).parent / "data" / "crt" / "msvc_v143.jsonl.gz",)


def get_default_databases() -> Sequence[LibraryStringDatabase]:
    return [LibraryStringDatabase.from_file(path) for path in DEFAULT_PATHS]


@dataclass
class WindowsApiStringDatabase:
    dll_names: set[str]
    api_names: set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def from_dir(cls, path: pathlib.Path) -> "WindowsApiStringDatabase":
        dll_names: Set[str] = set()
        api_names: Set[str] = set()

        for line in gzip.decompress((path / "dlls.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            dll_names.add(line)

        for line in gzip.decompress((path / "apis.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            api_names.add(line)

        return cls(dll_names=dll_names, api_names=api_names)

    @classmethod
    def from_defaults(cls) -> "WindowsApiStringDatabase":
        return cls.from_dir(pathlib.Path(__file__).parent / "data" / "winapi")

