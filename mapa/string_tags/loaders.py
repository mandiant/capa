from __future__ import annotations

import gzip
import hashlib
import logging
import re
from importlib import resources
from typing import Literal

import msgspec

logger = logging.getLogger(__name__)

HASH_DIGEST_SIZE = 8


class OpenSourceString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str | None = None
    function_name: str | None = None
    line_number: int | None = None


class ExpertRule(msgspec.Struct):
    type: Literal["string", "substring", "regex"]
    value: str
    tag: str
    action: Literal["mute", "highlight", "hide"]
    note: str
    description: str
    authors: list[str]
    references: list[str]


class StringGlobalPrevalence(msgspec.Struct):
    string: str
    encoding: str = "unknown"
    global_count: int = 0
    location: str | None = None


class OssDatabase:
    def __init__(self, entries: dict[str, OpenSourceString]):
        self.entries = entries

    def query(self, s: str) -> OpenSourceString | None:
        return self.entries.get(s)


class ExpertDatabase:
    def __init__(
        self,
        string_rules: dict[str, list[ExpertRule]],
        substring_rules: list[ExpertRule],
        regex_rules: list[tuple[ExpertRule, re.Pattern[str]]],
    ):
        self.string_rules = string_rules
        self.substring_rules = substring_rules
        self.regex_rules = regex_rules

    def query(self, s: str) -> list[ExpertRule]:
        hits: list[ExpertRule] = []
        for rule in self.string_rules.get(s, []):
            hits.append(rule)
        for rule in self.substring_rules:
            if rule.value in s:
                hits.append(rule)
        for rule, pattern in self.regex_rules:
            if pattern.search(s):
                hits.append(rule)
        return hits


class WinapiDatabase:
    def __init__(self, dll_names: set[str], api_names: set[str]):
        self.dll_names = dll_names
        self.api_names = api_names

    def query(self, s: str) -> bool:
        return s.lower() in self.dll_names or s in self.api_names


class GpJsonlDatabase:
    def __init__(self, entries: dict[str, list[StringGlobalPrevalence]]):
        self.entries = entries

    def query(self, s: str) -> list[StringGlobalPrevalence] | None:
        return self.entries.get(s)


class GpHashDatabase:
    def __init__(self, hashes: set[bytes]):
        self.hashes = hashes

    def query(self, s: str) -> bool:
        digest = hashlib.md5(s.encode("utf-8")).digest()[:HASH_DIGEST_SIZE]
        return digest in self.hashes


def _data_path():
    return resources.files("mapa.string_tags") / "data"


def _read_gzip_lines(path) -> list[bytes]:
    return gzip.decompress(path.read_bytes()).split(b"\n")


def load_oss_databases() -> list[OssDatabase]:
    decoder = msgspec.json.Decoder(OpenSourceString)
    dbs: list[OssDatabase] = []
    for subdir in ("oss", "crt"):
        data_dir = _data_path() / subdir
        for child in sorted(data_dir.iterdir()):
            if not child.name.endswith(".jsonl.gz"):
                continue
            entries: dict[str, OpenSourceString] = {}
            for line in _read_gzip_lines(child):
                line = line.strip()
                if not line:
                    continue
                record = decoder.decode(line)
                entries[record.string] = record
            dbs.append(OssDatabase(entries))
            logger.debug("loaded OSS database %s/%s: %d entries", subdir, child.name, len(entries))
    return dbs


def load_expert_database() -> ExpertDatabase:
    decoder = msgspec.json.Decoder(ExpertRule)
    path = _data_path() / "expert" / "capa.jsonl"
    string_rules: dict[str, list[ExpertRule]] = {}
    substring_rules: list[ExpertRule] = []
    regex_rules: list[tuple[ExpertRule, re.Pattern[str]]] = []

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rule = decoder.decode(line)
        if rule.type == "string":
            string_rules.setdefault(rule.value, []).append(rule)
        elif rule.type == "substring":
            substring_rules.append(rule)
        elif rule.type == "regex":
            try:
                regex_rules.append((rule, re.compile(rule.value)))
            except re.error:
                logger.warning("invalid regex in expert rule: %s", rule.value)

    logger.debug(
        "loaded expert database: %d string, %d substring, %d regex rules",
        len(string_rules),
        len(substring_rules),
        len(regex_rules),
    )
    return ExpertDatabase(string_rules, substring_rules, regex_rules)


def load_winapi_database() -> WinapiDatabase:
    winapi_dir = _data_path() / "winapi"
    dll_lines = _read_gzip_lines(winapi_dir / "dlls.txt.gz")
    api_lines = _read_gzip_lines(winapi_dir / "apis.txt.gz")
    dll_names = {line.decode("utf-8").strip().lower() for line in dll_lines if line.strip()}
    api_names = {line.decode("utf-8").strip() for line in api_lines if line.strip()}
    logger.debug("loaded winapi database: %d dlls, %d apis", len(dll_names), len(api_names))
    return WinapiDatabase(dll_names, api_names)


def load_gp_jsonl_databases() -> list[GpJsonlDatabase]:
    decoder = msgspec.json.Decoder(StringGlobalPrevalence)
    gp_dir = _data_path() / "gp"
    dbs: list[GpJsonlDatabase] = []
    for name in ("gp.jsonl.gz", "cwindb-native.jsonl.gz", "cwindb-dotnet.jsonl.gz"):
        entries: dict[str, list[StringGlobalPrevalence]] = {}
        lines = _read_gzip_lines(gp_dir / name)
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            if i == 0:
                continue
            record = decoder.decode(line)
            entries.setdefault(record.string, []).append(record)
        dbs.append(GpJsonlDatabase(entries))
        logger.debug("loaded GP JSONL database %s: %d entries", name, len(entries))
    return dbs


def load_junk_code_database() -> GpJsonlDatabase:
    decoder = msgspec.json.Decoder(StringGlobalPrevalence)
    path = _data_path() / "gp" / "junk-code.jsonl.gz"
    entries: dict[str, list[StringGlobalPrevalence]] = {}
    lines = _read_gzip_lines(path)
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        if i == 0:
            continue
        record = decoder.decode(line)
        entries.setdefault(record.string, []).append(record)
    logger.debug("loaded junk-code database: %d entries", len(entries))
    return GpJsonlDatabase(entries)


def load_gp_hash_databases() -> list[GpHashDatabase]:
    gp_dir = _data_path() / "gp"
    dbs: list[GpHashDatabase] = []
    for name in ("xaa-hashes.bin", "yaa-hashes.bin"):
        data = (gp_dir / name).read_bytes()
        hashes: set[bytes] = set()
        for offset in range(0, len(data), HASH_DIGEST_SIZE):
            chunk = data[offset : offset + HASH_DIGEST_SIZE]
            if len(chunk) == HASH_DIGEST_SIZE:
                hashes.add(chunk)
        dbs.append(GpHashDatabase(hashes))
        logger.debug("loaded GP hash database %s: %d entries", name, len(hashes))
    return dbs
