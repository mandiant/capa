# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import functools
import contextlib
import collections
from typing import Tuple, Union, Iterator
from pathlib import Path
from dataclasses import field, dataclass

import pytest

import capa.rules
import capa.engine as ceng
import capa.render.result_document
from capa.features.common import OS_AUTO, FORMAT_AUTO, Feature
from capa.features.address import Address
from capa.features.extractors.script import LANG_CS, LANG_PY
from capa.features.extractors.base_extractor import (
    BBHandle,
    CallHandle,
    InsnHandle,
    ThreadHandle,
    ProcessHandle,
    FunctionHandle,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)
from capa.features.extractors.dnfile.extractor import DnfileFeatureExtractor

logger = logging.getLogger(__name__)
CD = Path(__file__).resolve().parent
DOTNET_DIR = CD / "data" / "dotnet"
SOURCE_DIR = CD / "data" / "source"
ASPX_DIR = SOURCE_DIR / "aspx"
CS_DIR = SOURCE_DIR / "cs"
PY_DIR = SOURCE_DIR / "py"
DNFILE_TESTFILES = DOTNET_DIR / "dnfile-testfiles"


def parse_feature_string(s: str) -> Feature | ceng.Range | ceng.Statement:
    """
    parse a feature from a single string
    no extra description is assigned.

    examples:
        "mnemonic: mov"
        "string: /foo/"
        "count(basic blocks): 7"

    returns: Range if the feature is a count, and generated Statement for COM features, otherwise Feature.
    """
    key, _, value = s.partition(": ")
    return capa.rules.build_feature(key, value, initial_description=None)


KNOWN_FEATURE_NAMES = {
    "api",
    "arch",
    "basic blocks",
    "bytes",
    "characteristic",
    "class",
    "export",
    "format",
    "function-name",
    "import",
    "mnemonic",
    "namespace",
    "number",
    "offset",
    "operand[0].number",
    "operand[0].offset",
    "operand[1].number",
    "operand[1].offset",
    "operand[2].offset",
    "os",
    "property",
    "property/read",
    "property/write",
    "section",
    "string",
    "substring",
}

KNOWN_SCOPE_NAMES = capa.rules.STATIC_SCOPES | capa.rules.DYNAMIC_SCOPES

KNOWN_FIXTURE_TAGS: set[str] = (
    {
        "static",  # static analysis test, PE/ELF format.
        "dynamic",  # dynamic analysis test
        "dotnet",  # .NET format
        "elf",  # ELF format
        "flirt",  # requires FLIRT signature matching
        "binja-db",  # Binary Ninja database format
        "binexport",  # BinExport2 format
        "aarch64",  # AArch64 architecture
        "cape",  # CAPE analysis
        "drakvuf",  # Drakvuf analysis
        "vmray",  # VMRay analysis
    }
    | KNOWN_SCOPE_NAMES
    | KNOWN_FEATURE_NAMES
)


def get_scope_from_location(location: str) -> capa.rules.Scope:
    """
    classify a fixture location string into a scope kind.

    reuses the same location grammar handled by `resolve_scope()`.
    """
    if location == "file":
        return capa.rules.Scope.FILE
    if "insn=" in location:
        return capa.rules.Scope.INSTRUCTION
    if "bb=" in location:
        return capa.rules.Scope.BASIC_BLOCK
    if "call=" in location:
        return capa.rules.Scope.CALL
    if "thread=" in location:
        return capa.rules.Scope.THREAD
    if "process=" in location:
        return capa.rules.Scope.PROCESS
    if location.startswith(("function", "token")):
        return capa.rules.Scope.FUNCTION
    raise ValueError(f"unexpected scope location: {location}")


@dataclass(frozen=True)
class FixtureMark:
    backend: (
        Literal["vivisect"]
        | Literal["dotnet"]
        | Literal["binja"]
        | Literal["pefile"]
        | Literal["cape"]
        | Literal["drakvuf"]
        | Literal["vmray"]
        | Literal["freeze"]
        | Literal["binexport2"]
        | Literal["ida"]
        | Literal["ghidra"]
    )
    mark: Literal["skip"] | Literal["xfail"]
    reason: str


@dataclass(frozen=True)
class FixtureFile:
    key: str
    path: Path
    tags: frozenset[str] = frozenset()


@dataclass(frozen=True)
class FeatureFixture:
    sample_key: str
    sample_path: Path
    location: str
    scope: capa.rules.Scope
    statement: Union[Feature, ceng.Range, ceng.Statement]
    expected: bool = True
    tags: frozenset[str] = frozenset()
    marks: tuple[FixtureMark, ...] = ()
    explanation: Optional[str] = None


@dataclass(frozen=True)
class BackendFeaturePolicy:
    name: str
    include_tags: set[str] = field(default_factory=set)
    exclude_tags: set[str] = field(default_factory=set)


def get_fixture_files() -> tuple[tuple[Path, dict], ...]:
    manifests = []
    for path in sorted(FIXTURE_MANIFEST_DIR.glob("*.json")):
        with path.open("r") as f:
            manifests.append((path, json.load(f)))
    if not manifests:
        raise ValueError(f"no fixture manifests found in {FIXTURE_MANIFEST_DIR}")
    return tuple(manifests)


def load_fixture_file_references() -> dict[str, FixtureFile]:
    """
    load the combined `files` tables from `tests/fixtures/features/*.json`.

    file entries may include a `tags` list that will be inherited
    by feature fixtures that reference the file.
    """
    files: dict[str, FixtureFile] = {}
    file_sources: dict[str, Path] = {}
    for manifest_path, data in get_fixture_files():
        for entry in data["files"]:
            key = entry["key"]
            if key in files:
                raise ValueError(f"duplicate fixture file key {key!r} in {file_sources[key]} and {manifest_path}")

            tags = frozenset(entry.get("tags", []))
            unknown = tags - KNOWN_FIXTURE_TAGS
            if unknown:
                raise ValueError(f"unknown fixture tag(s) on file {key!r} in {manifest_path}: {sorted(unknown)}")
            files[key] = FixtureFile(
                key=key,
                path=CD / entry["path"],
                tags=tags,
            )
            file_sources[key] = manifest_path
    return files


def load_feature_fixtures() -> tuple[FeatureFixture, ...]:
    """
    load the full list of feature fixtures from `tests/fixtures/features/*.json`.

    merges file-level tags into feature-level tags, validates tags against
    the known registry, parses the statement (including `count(...)`), and
    defaults `expected` to True.
    """
    fixture_file_references = load_fixture_file_references()
    fixtures_: list[FeatureFixture] = []
    for fixture_file_path, fixture_file_data in get_fixture_files():
        for fixture_file_entry in fixture_file_data["features"]:
            fixture_file_reference = fixture_file_entry["file"]
            if fixture_file_reference not in fixture_file_references:
                raise ValueError(
                    f"unknown fixture file key referenced by feature in {fixture_file_path}: {fixture_file_reference!r}"
                )
            fixture_file = fixture_file_references[fixture_file_reference]

            feature_str: str = fixture_file_entry["feature"]
            tags = frozenset(fixture_file_entry.get("tags", [])) | fixture_file.tags
            unknown = tags - KNOWN_FIXTURE_TAGS
            if unknown:
                raise ValueError(
                    f"unknown fixture tag(s) on feature {feature_str!r} for file {fixture_file_reference!r} in {fixture_file_path}: {sorted(unknown)}"
                )

            location = fixture_file_entry["location"]
            statement = parse_feature_string(feature_str)
            scope = get_scope_from_location(location)
            # scope-kind and feature-type tags are auto-derived so that
            # backend policies can include/exclude scopes and feature types
            # purely via `include_tags`/`exclude_tags`. they're drawn from
            # the known-tag registry so no re-validation is needed here.
            tags = tags | {scope.value}
            if isinstance(statement, Feature):
                tags = tags | {statement.name}
                # technically we're not extracting the feature name for COM and count features
                # but i think thats ok for now, since no tests rely on include/excluding those.

            expected = fixture_file_entry.get("expected", True)
            marks = tuple(
                FixtureMark(backend=m["backend"], mark=m["mark"], reason=m["reason"])
                for m in fixture_file_entry.get("marks", [])
            )

            fixtures_.append(
                FeatureFixture(
                    sample_key=fixture_file_reference,
                    sample_path=fixture_file.path,
                    location=location,
                    scope=scope,
                    statement=statement,
                    expected=expected,
                    tags=tags,
                    marks=marks,
                    explanation=fixture_file_entry.get("explanation"),
                )
            )

    fixtures_.sort(key=lambda f: (f.sample_key, f.location))
    return tuple(fixtures_)


def _fixture_is_included(policy: BackendFeaturePolicy, fixture: FeatureFixture) -> bool:
    """decide whether a fixture is selected by a policy."""
    if policy.include_tags and not (fixture.tags & policy.include_tags):
        return False
    if fixture.tags & policy.exclude_tags:
        return False
    return True


def select_feature_fixtures(policy: BackendFeaturePolicy) -> list[FeatureFixture]:
    """
    select fixtures matching a backend policy.

    rules (applied in order):
      1. start from all fixtures
      2. if `include_tags` is non-empty, keep fixtures whose tags intersect it
      3. drop fixtures whose tags intersect `exclude_tags`

    scope kinds and feature types are exposed as auto-derived tags, so
    a policy can restrict scope or feature type via `exclude_tags` too.
    """
    return [f for f in load_feature_fixtures() if _fixture_is_included(policy, f)]


def _fixture_test_id(fixture: FeatureFixture) -> str:
    """
    build a readable pytest parameter id for a fixture.

    mirrors the legacy `make_test_id` shape: sample-location-statement-expected.
    """
    return "-".join([
        fixture.sample_key,
        fixture.location,
        str(fixture.statement),
        str(fixture.expected),
    ])


def parametrize_backend_feature_fixtures(policy: BackendFeaturePolicy):
    """
    build a pytest parametrize decorator for a backend's selected fixtures.

    applies JSON marks matching `policy.name` to the parameter set, so
    backend-specific skip/xfail behavior stays in the JSON data file.
    """
    selected = select_feature_fixtures(policy)
    params = []
    for fixture in selected:
        marks = []
        for mark in fixture.marks:
            if mark.backend != policy.name:
                continue
            if mark.mark == "skip":
                marks.append(pytest.mark.skip(reason=mark.reason))
            elif mark.mark == "xfail":
                marks.append(pytest.mark.xfail(reason=mark.reason))
            else:
                raise ValueError(f"unknown mark {mark.mark!r} for backend {policy.name!r}")
        params.append(pytest.param(fixture, marks=marks, id=_fixture_test_id(fixture)))
    return pytest.mark.parametrize("feature_fixture", params)


def run_feature_fixture(
    extractor: StaticFeatureExtractor | DynamicFeatureExtractor,
    fixture: FeatureFixture,
) -> None:
    """
    generic runner that evaluates a feature fixture against a backend.
    """
    scope = resolve_scope(fixture.location)
    features = scope(extractor)
    result = fixture.statement.evaluate(features)
    actual = bool(result)
    if fixture.expected:
        msg = f"{fixture.statement} should match in {fixture.location}"
    else:
        msg = f"{fixture.statement} should not match in {fixture.location}"
    assert actual == fixture.expected, msg


@lru_cache(maxsize=1)
def get_ts_extractor_engine(language, buf):
    import capa.features.extractors.ts.engine

    return capa.features.extractors.ts.engine.TreeSitterExtractorEngine(language, buf)


@lru_cache(maxsize=1)
def get_ts_template_engine(path):
    import capa.features.extractors.ts.engine

    with Path(path).open("rb") as f:
        buf = f.read()
    return capa.features.extractors.ts.engine.TreeSitterTemplateEngine(buf)


@lru_cache(maxsize=1)
def get_ts_extractor(path):
    import capa.features.extractors.ts.extractor

    return capa.features.extractors.ts.extractor.TreeSitterFeatureExtractor(path)


def extract_global_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_global_features():
        features[feature].add(va)
    return features


@functools.lru_cache
def extract_file_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_file_features():
        features[feature].add(va)
    return features


def extract_process_features(extractor, ph):
    features = collections.defaultdict(set)
    for th in extractor.get_threads(ph):
        for ch in extractor.get_calls(ph, th):
            for feature, va in extractor.extract_call_features(ph, th, ch):
                features[feature].add(va)
        for feature, va in extractor.extract_thread_features(ph, th):
            features[feature].add(va)
    for feature, va in extractor.extract_process_features(ph):
        features[feature].add(va)
    return features


def extract_thread_features(extractor, ph, th):
    features = collections.defaultdict(set)
    for ch in extractor.get_calls(ph, th):
        for feature, va in extractor.extract_call_features(ph, th, ch):
            features[feature].add(va)
    for feature, va in extractor.extract_thread_features(ph, th):
        features[feature].add(va)
    return features


def extract_call_features(extractor, ph, th, ch):
    features = collections.defaultdict(set)
    for feature, addr in extractor.extract_call_features(ph, th, ch):
        features[feature].add(addr)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @functools.lru_cache this
def extract_function_features(extractor, fh):
    features = collections.defaultdict(set)
    for bb in extractor.get_basic_blocks(fh):
        for insn in extractor.get_instructions(fh, bb):
            for feature, va in extractor.extract_insn_features(fh, bb, insn):
                features[feature].add(va)
        for feature, va in extractor.extract_basic_block_features(fh, bb):
            features[feature].add(va)
    for feature, va in extractor.extract_function_features(fh):
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @functools.lru_cache this
def extract_basic_block_features(extractor, fh, bbh):
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(fh, bbh):
        for feature, va in extractor.extract_insn_features(fh, bbh, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(fh, bbh):
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @functools.lru_cache this
def extract_instruction_features(extractor, fh, bbh, ih) -> dict[Feature, set[Address]]:
    features = collections.defaultdict(set)
    for feature, addr in extractor.extract_insn_features(fh, bbh, ih):
        features[feature].add(addr)
    return features


# note: to reduce the testing time it's recommended to reuse already existing test samples, if possible
def get_data_path_by_name(name) -> Path:
    if name == "mimikatz":
        return CD / "data" / "mimikatz.exe_"
    elif name == "kernel32":
        return CD / "data" / "kernel32.dll_"
    elif name == "kernel32-64":
        return CD / "data" / "kernel32-64.dll_"
    elif name == "pma01-01":
        return CD / "data" / "Practical Malware Analysis Lab 01-01.dll_"
    elif name == "pma01-01-rd":
        return CD / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json"
    elif name == "pma12-04":
        return CD / "data" / "Practical Malware Analysis Lab 12-04.exe_"
    elif name == "pma16-01":
        return CD / "data" / "Practical Malware Analysis Lab 16-01.exe_"
    elif name == "pma16-01_binja_db":
        return CD / "data" / "Practical Malware Analysis Lab 16-01.exe_.bndb"
    elif name == "pma21-01":
        return CD / "data" / "Practical Malware Analysis Lab 21-01.exe_"
    elif name == "al-khaser x86":
        return CD / "data" / "al-khaser_x86.exe_"
    elif name == "al-khaser x64":
        return CD / "data" / "al-khaser_x64.exe_"
    elif name.startswith("39c05"):
        return CD / "data" / "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_"
    elif name.startswith("499c2"):
        return CD / "data" / "499c2a85f6e8142c3f48d4251c9c7cd6.raw32"
    elif name.startswith("9324d"):
        return CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_"
    elif name.startswith("395eb"):
        return CD / "data" / "395eb0ddd99d2c9e37b6d0b73485ee9c.exe_"
    elif name.startswith("a1982"):
        return CD / "data" / "a198216798ca38f280dc413f8c57f2c2.exe_"
    elif name.startswith("a933a"):
        return CD / "data" / "a933a1a402775cfa94b6bee0963f4b46.dll_"
    elif name.startswith("bfb9b"):
        return CD / "data" / "bfb9b5391a13d0afd787e87ab90f14f5.dll_"
    elif name.startswith("c9188"):
        return CD / "data" / "c91887d861d9bd4a5872249b641bc9f9.exe_"
    elif name.startswith("64d9f"):
        return CD / "data" / "64d9f7d96b99467f36e22fada623c3bb.dll_"
    elif name.startswith("82bf6"):
        return CD / "data" / "82BF6347ACF15E5D883715DC289D8A2B.exe_"
    elif name.startswith("pingtaest"):
        return CD / "data" / "ping_täst.exe_"
    elif name.startswith("77329"):
        return CD / "data" / "773290480d5445f11d3dc1b800728966.exe_"
    elif name.startswith("3b13b"):
        return CD / "data" / "3b13b6f1d7cd14dc4a097a12e2e505c0a4cff495262261e2bfc991df238b9b04.dll_"
    elif name == "7351f.elf":
        return CD / "data" / "7351f8a40c5450557b24622417fc478d.elf_"
    elif name.startswith("79abd"):
        return CD / "data" / "79abd17391adc6251ecdc58d13d76baf.dll_"
    elif name.startswith("946a9"):
        return CD / "data" / "946a99f36a46d335dec080d9a4371940.dll_"
    elif name.startswith("2f7f5f"):
        return CD / "data" / "2f7f5fb5de175e770d7eae87666f9831.elf_"
    elif name.startswith("b9f5b"):
        return CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_"
    elif name.startswith("mixed-mode-64"):
        return DNFILE_TESTFILES / "mixed-mode" / "ModuleCode" / "bin" / "ModuleCode_amd64.exe"
    elif name.startswith("hello-world"):
        return DNFILE_TESTFILES / "hello-world" / "hello-world.exe"
    elif name.startswith("_1c444"):
        return DOTNET_DIR / "1c444ebeba24dcba8628b7dfe5fec7c6.exe_"
    elif name.startswith("_387f15"):
        return DOTNET_DIR / "387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_"
    elif name.startswith("_692f"):
        return DOTNET_DIR / "692f7fd6d198e804d6af98eb9e390d61.exe_"
    elif name.startswith("_0953c"):
        return CD / "data" / "0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_"
    elif name.startswith("_039a6"):
        return CD / "data" / "039a6336d0802a2255669e6867a5679c7eb83313dbc61fb1c7232147379bd304.exe_"
    elif name.startswith("b5f052"):
        return CD / "data" / "b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_"
    elif name.startswith("bf7a9c"):
        return CD / "data" / "bf7a9c8bdfa6d47e01ad2b056264acc3fd90cf43fe0ed8deec93ab46b47d76cb.elf_"
    elif name.startswith("294b8d"):
        return CD / "data" / "294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc.elf_"
    elif name.startswith("2bf18d"):
        return CD / "data" / "2bf18d0403677378adad9001b1243211.elf_"
    elif name.startswith("0000a657"):
        return (
            CD
            / "data"
            / "dynamic"
            / "cape"
            / "v2.2"
            / "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"
        )
    elif name.startswith("d46900"):
        return (
            CD
            / "data"
            / "dynamic"
            / "cape"
            / "v2.2"
            / "d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7.json.gz"
        )
    elif name.startswith("93b2d1-drakvuf"):
        return (
            CD
            / "data"
            / "dynamic"
            / "drakvuf"
            / "93b2d1840566f45fab674ebc79a9d19c88993bcb645e0357f3cb584d16e7c795.log.gz"
        )
    elif name.startswith("93b2d1-vmray"):
        return (
            CD
            / "data"
            / "dynamic"
            / "vmray"
            / "93b2d1840566f45fab674ebc79a9d19c88993bcb645e0357f3cb584d16e7c795_min_archive.zip"
        )
    elif name.startswith("2f8a79-vmray"):
        return (
            CD
            / "data"
            / "dynamic"
            / "vmray"
            / "2f8a79b12a7a989ac7e5f6ec65050036588a92e65aeb6841e08dc228ff0e21b4_min_archive.zip"
        )
    elif name.startswith("eb1287-vmray"):
        return (
            CD
            / "data"
            / "dynamic"
            / "vmray"
            / "eb12873c0ce3e9ea109c2a447956cbd10ca2c3e86936e526b2c6e28764999f21_min_archive.zip"
        )
    elif name.startswith("ea2876"):
        return CD / "data" / "ea2876e9175410b6f6719f80ee44b9553960758c7d0f7bed73c0fe9a78d8e669.dll_"
    elif name.startswith("1038a2"):
        return CD / "data" / "1038a23daad86042c66bfe6c9d052d27048de9653bde5750dc0f240c792d9ac8.elf_"
    elif name.startswith("3da7c"):
        return CD / "data" / "3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
    elif name.startswith("nested_typedef"):
        return CD / "data" / "dotnet" / "dd9098ff91717f4906afe9dafdfa2f52.exe_"
    elif name.startswith("nested_typeref"):
        return CD / "data" / "dotnet" / "2c7d60f77812607dec5085973ff76cea.dll_"
    elif name.startswith("687e79.ghidra.be2"):
        return (
            CD
            / "data"
            / "binexport2"
            / "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_.ghidra.BinExport"
        )
    elif name.startswith("d1e650.ghidra.be2"):
        return (
            CD
            / "data"
            / "binexport2"
            / "d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_.ghidra.BinExport"
        )
    else:
        raise ValueError(f"unexpected sample fixture: {name}")


ASPX_DATA_PATH_BY_NAME = {
    "aspx_4f6fa6": ASPX_DIR / "4f6fa6a45017397c7e1c9cd5a17235ccb1ff0f5087dfa6b7384552bf507e7fe1.aspx_",
    "aspx_5f959f": ASPX_DIR / "5f959f480a66a33d37d9a0ef6c8f7d0059625ca2a8ae9236b49b194733622655.aspx_",
    "aspx_10162f": ASPX_DIR / "10162feb5f063ea09c6a3d275f31abf0fe8a9e4e36fded0053b1f8e054da8161.aspx_",
    "aspx_2b71dd": ASPX_DIR / "2b71dd245520d9eb5f1e4c633fee61c7d83687591d9f64f9390c26dc95057c3c.aspx_",
    "aspx_f2bf20": ASPX_DIR / "f2bf20e7bb482d27da8f19aa0f8bd4927746a65300929b99166867074a38a4b4.aspx_",
    "aspx_f39dc0": ASPX_DIR / "f39dc0dfd43477d65c1380a7cff89296ad72bfa7fc3afcfd8e294f195632030e.aspx_",
    "aspx_ea2a01": ASPX_DIR / "ea2a01cae57c00df01bff6bb8a72585fdc0abb7a26a869dc1a0131bdff50b400.aspx_",
    "aspx_6f3261": ASPX_DIR / "6f3261eaaabf369bd928d179641b73ffd768184dfd4e00124da462a3075d4239.aspx_",
    "aspx_1f8f40": ASPX_DIR / "1f8f4054932ed1d5d055e9a92aa1e2abba49af3370506674cb1b2c70146ae81a.aspx_",
    "aspx_2e8c7e": ASPX_DIR / "2e8c7eacd739ca3f3dc4112b41a024157035096b8d0c26ba79d8b893136391bc.aspx_",
    "aspx_03bb5c": ASPX_DIR / "03bb5cab46b406bb8613ca6e32991ab3e10b5cd759d5c7813191e9e62868ea73.aspx_",
    "aspx_606dbf": ASPX_DIR / "606dbfebdc7751ecb6cb9a845853ae1905afd4b8a2cb54e1e4a98c932e268712.aspx_",
    "aspx_f397cb": ASPX_DIR / "f397cb676353873cdc8fcfbf0e3a317334353cc63946099e5ea22db6d1eebfb8.aspx_",
    "aspx_b4bb14": ASPX_DIR / "b4bb14aeb692f7afc107ee89f86d096f1cd8f9761b6c50788f626a9dccc8b077.aspx_",
    "aspx_54433d": ASPX_DIR / "54433dd57414773098a6d3292d262f91a6812855dfcbf8d421695608d1fad638.aspx_",
    "aspx_a35878": ASPX_DIR / "a35878e74425cd97ad98e3ec4b2583867bb536f4275d821cd8b82bc19380ba1a.aspx_",
    "aspx_a5c893": ASPX_DIR / "a5c8934836f5b36bba3a722eab691a9f1f926c138fefe5bae07e9074e7c49ae3.aspx_",
    "aspx_15eed4": ASPX_DIR / "15eed42e4904205b2ef2ff285ff1ce6c8138296c12cf075a2562c69a5fafd1cb.aspx_",
    "aspx_b75f16": ASPX_DIR / "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0.aspx_",
    "aspx_d460ca": ASPX_DIR / "d460cae7d34c51059ef57c5aadb3de099469efbac5fffcf76d0528a511192a28.aspx_",
}

CS_DATA_PATH_BY_NAME = {
    "cs_138cdc": CS_DIR / "138cdc4b10f3f5ece9c47bb0ec17fde5b70c1f9a90b267794c5e5dfa337fc798.cs_",
}

PY_DATA_PATH_BY_NAME = {
    "py_7f9cd1": PY_DIR / "7f9cd1eedf0a9088fc3e07a275d04dceadcf0a5cd425a17e9666b63685d3a37e.py_",
    "py_ca0df6": PY_DIR / "ca0df6cccf2a15ce8f781d81959cf230aead64e6297a3283b21457dc74938c89.py_",
}


def get_sample_md5_by_name(name):
    """used by IDA tests to ensure the correct IDB is loaded"""
    if name == "mimikatz":
        return "5f66b82558ca92e54e77f216ef4c066c"
    elif name == "kernel32":
        return "e80758cf485db142fca1ee03a34ead05"
    elif name == "kernel32-64":
        return "a8565440629ac87f6fef7d588fe3ff0f"
    elif name == "pma12-04":
        return "56bed8249e7c2982a90e54e1e55391a2"
    elif name == "pma16-01":
        return "7faafc7e4a5c736ebfee6abbbc812d80"
    elif name == "pma01-01":
        return "290934c61de9176ad682ffdd65f0a669"
    elif name == "pma21-01":
        return "c8403fb05244e23a7931c766409b5e22"
    elif name == "al-khaser x86":
        return "db648cd247281954344f1d810c6fd590"
    elif name == "al-khaser x64":
        return "3cb21ae76ff3da4b7e02d77ff76e82be"
    elif name.startswith("39c05"):
        return "b7841b9d5dc1f511a93cc7576672ec0c"
    elif name.startswith("499c2"):
        return "499c2a85f6e8142c3f48d4251c9c7cd6"
    elif name.startswith("9324d"):
        return "9324d1a8ae37a36ae560c37448c9705a"
    elif name.startswith("a1982"):
        return "a198216798ca38f280dc413f8c57f2c2"
    elif name.startswith("a933a"):
        return "a933a1a402775cfa94b6bee0963f4b46"
    elif name.startswith("bfb9b"):
        return "bfb9b5391a13d0afd787e87ab90f14f5"
    elif name.startswith("c9188"):
        return "c91887d861d9bd4a5872249b641bc9f9"
    elif name.startswith("64d9f"):
        return "64d9f7d96b99467f36e22fada623c3bb"
    elif name.startswith("82bf6"):
        return "82bf6347acf15e5d883715dc289d8a2b"
    elif name.startswith("77329"):
        return "773290480d5445f11d3dc1b800728966"
    elif name.startswith("3b13b"):
        # file name is SHA256 hash
        return "56a6ffe6a02941028cc8235204eef31d"
    elif name.startswith("7351f"):
        return "7351f8a40c5450557b24622417fc478d"
    elif name.startswith("79abd"):
        return "79abd17391adc6251ecdc58d13d76baf"
    elif name.startswith("946a9"):
        return "946a99f36a46d335dec080d9a4371940"
    elif name.startswith("b9f5b"):
        return "b9f5bd514485fb06da39beff051b9fdc"
    elif name.startswith("294b8d"):
        # file name is SHA256 hash
        return "3db3e55b16a7b1b1afb970d5e77c5d98"
    elif name.startswith("2bf18d"):
        return "2bf18d0403677378adad9001b1243211"
    elif name.startswith("ea2876"):
        return "76fa734236daa023444dec26863401dc"
    else:
        raise ValueError(f"unexpected sample fixture: {name}")


def resolve_sample(sample):
    return get_data_path_by_name(sample)


@pytest.fixture
def sample(request):
    return resolve_sample(request.param)


def get_process(extractor, ppid: int, pid: int) -> ProcessHandle:
    for ph in extractor.get_processes():
        if ph.address.ppid == ppid and ph.address.pid == pid:
            return ph
    raise ValueError("process not found")


def get_thread(extractor, ph: ProcessHandle, tid: int) -> ThreadHandle:
    for th in extractor.get_threads(ph):
        if th.address.tid == tid:
            return th
    raise ValueError("thread not found")


def get_call(extractor, ph: ProcessHandle, th: ThreadHandle, cid: int) -> CallHandle:
    for ch in extractor.get_calls(ph, th):
        if ch.address.id == cid:
            return ch
    raise ValueError("call not found")


def resolve_sample_ts(sample):
    if sample.startswith("cs_"):
        try:
            return CS_DATA_PATH_BY_NAME[sample]
        except KeyError:
            raise ValueError(f"unexpected sample fixture: {sample}")
    if sample.startswith("py_"):
        return PY_DATA_PATH_BY_NAME[sample]
    if sample.startswith("aspx_"):
        try:
            return ASPX_DATA_PATH_BY_NAME[sample]
        except KeyError:
            raise ValueError(f"unexpected sample fixture: {sample}")
    raise ValueError(f"unexpected sample fixture: {sample}")


@pytest.fixture
def sample_ts(request):
    return resolve_sample_ts(request.param)


def get_function(extractor, fva: int) -> FunctionHandle:
    for fh in extractor.get_functions():
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = fh.inner.offset
        else:
            addr = fh.address
        if addr == fva:
            return fh
    raise ValueError("function not found")


def get_function_ts(extractor, fid: Union[Tuple[int], str]) -> Iterator[FunctionHandle]:
    for fh in extractor.get_functions():
        if isinstance(fid, tuple):
            addr = (fh.address.start_byte, fh.address.end_byte)
        elif isinstance(fid, str):
            addr = fh.inner.name
        else:
            raise ValueError("invalid fva format")

        if addr == fid:
            yield fh


def get_function_by_token(extractor, token: int) -> FunctionHandle:
    for fh in extractor.get_functions():
        if fh.address == token:
            return fh
    raise ValueError("function not found by token")


def get_basic_block(extractor, fh: FunctionHandle, va: int) -> BBHandle:
    for bbh in extractor.get_basic_blocks(fh):
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = bbh.inner.offset
        else:
            addr = bbh.address
        if addr == va:
            return bbh
    raise ValueError("basic block not found")


def get_instruction(extractor, fh: FunctionHandle, bbh: BBHandle, va: int) -> InsnHandle:
    for ih in extractor.get_instructions(fh, bbh):
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = ih.inner.offset
        else:
            addr = ih.address
        if addr == va:
            return ih
    raise ValueError("instruction not found")


def resolve_scope(scope):
    if scope == "file":

        def inner_file(extractor):
            features = extract_file_features(extractor)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_file.__name__ = scope
        return inner_file
    elif "insn=" in scope:
        # like `function=0x401000,bb=0x40100A,insn=0x40100A`
        assert "function=" in scope
        assert "bb=" in scope
        assert "insn=" in scope
        fspec, _, spec = scope.partition(",")
        bbspec, _, ispec = spec.partition(",")
        fva = int(fspec.partition("=")[2], 0x10)
        bbva = int(bbspec.partition("=")[2], 0x10)
        iva = int(ispec.partition("=")[2], 0x10)

        def inner_insn(extractor):
            fh = get_function(extractor, fva)
            bbh = get_basic_block(extractor, fh, bbva)
            ih = get_instruction(extractor, fh, bbh, iva)
            features = extract_instruction_features(extractor, fh, bbh, ih)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_insn.__name__ = scope
        return inner_insn
    elif "bb=" in scope:
        # like `function=0x401000,bb=0x40100A`
        assert "function=" in scope
        assert "bb=" in scope
        fspec, _, bbspec = scope.partition(",")
        fva = int(fspec.partition("=")[2], 0x10)
        bbva = int(bbspec.partition("=")[2], 0x10)

        def inner_bb(extractor):
            fh = get_function(extractor, fva)
            bbh = get_basic_block(extractor, fh, bbva)
            features = extract_basic_block_features(extractor, fh, bbh)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_bb.__name__ = scope
        return inner_bb
    elif scope.startswith(("function", "token")):
        # like `function=0x401000` or `token=0x6000001`
        va = int(scope.partition("=")[2], 0x10)

        def inner_function(extractor):
            if scope.startswith("token"):
                fh = get_function_by_token(extractor, va)
            else:
                fh = get_function(extractor, va)
            features = extract_function_features(extractor, fh)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_function.__name__ = scope
        return inner_function
    elif "call=" in scope:
        # like `process=(pid:ppid),thread=tid,call=id`
        assert "process=" in scope
        assert "thread=" in scope
        pspec, _, spec = scope.partition(",")
        tspec, _, cspec = spec.partition(",")
        pspec = pspec.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)
        tid = int(tspec.partition("=")[2])
        cid = int(cspec.partition("=")[2])

        def inner_call(extractor):
            ph = get_process(extractor, ppid, pid)
            th = get_thread(extractor, ph, tid)
            ch = get_call(extractor, ph, th, cid)
            features = extract_call_features(extractor, ph, th, ch)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_call.__name__ = scope
        return inner_call
    elif "thread=" in scope:
        # like `process=(pid:ppid),thread=tid`
        assert "process=" in scope
        pspec, _, tspec = scope.partition(",")
        pspec = pspec.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)
        tid = int(tspec.partition("=")[2])

        def inner_thread(extractor):
            ph = get_process(extractor, ppid, pid)
            th = get_thread(extractor, ph, tid)
            features = extract_thread_features(extractor, ph, th)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_thread.__name__ = scope
        return inner_thread
    elif "process=" in scope:
        # like `process=(pid:ppid)`
        pspec = scope.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)

        def inner_process(extractor):
            ph = get_process(extractor, ppid, pid)
            features = extract_process_features(extractor, ph)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_process.__name__ = scope
        return inner_process
    else:
        raise ValueError("unexpected scope fixture")


@pytest.fixture
def scope(request):
    return resolve_scope(request.param)


def get_function_id_ts(scope):
    fid = scope.partition("=")[2]
    if fid[0] == "(" and fid[-1] == ")":
        fid = tuple(int(x, 16) if x.lstrip().startswith("0x") else int(x) for x in fid[1:-1].split(","))
    return fid


def resolve_scope_ts(scope):
    if scope == "global":

        def inner_fn(extractor):
            return extract_global_features(extractor)

    elif scope == "file":

        def inner_fn(extractor):
            features = extract_file_features(extractor)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

    elif scope.startswith("function"):
        # like `function=(0xbeef, 0xdead) or function=(123, 456) or function=foo_bar`
        def inner_fn(extractor):
            fid = get_function_id_ts(scope)
            fhs = list(get_function_ts(extractor, fid))
            if not fhs:
                raise ValueError("function not found")
            features = collections.defaultdict(set)
            for fh in fhs:
                for k, vs in extract_function_features(extractor, fh).items():
                    # print(f"{k}:{vs}")
                    features[k].update(vs)
            for k, vs in extract_file_features(extractor).items():
                features[k].update(vs)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

    else:
        raise ValueError("unexpected scope fixture")
    inner_fn.__name__ = scope
    return inner_fn


@pytest.fixture
def scope_ts(request):
    return resolve_scope_ts(request.param)


def make_test_id(values):
    return "-".join(map(str, values))


def parametrize(params, values, **kwargs):
    """
    extend `pytest.mark.parametrize` to pretty-print features.
    by default, it renders objects as an opaque value.
    ref: https://docs.pytest.org/en/2.9.0/example/parametrize.html#different-options-for-test-ids
    rendered ID might look something like:
        mimikatz-function=0x403BAC-api(CryptDestroyKey)-True
    """
    ids = list(map(make_test_id, values))
    return pytest.mark.parametrize(params, values, ids=ids, **kwargs)


def get_result_doc(path: Path):
    return capa.render.result_document.ResultDocument.from_file(path)


@pytest.fixture
def pma0101_rd():
    # python -m capa.main tests/data/Practical\ Malware\ Analysis\ Lab\ 01-01.dll_ --json > tests/data/rd/Practical\ Malware\ Analysis\ Lab\ 01-01.dll_.json
    return get_result_doc(CD / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json")


@pytest.fixture
def dotnet_1c444e_rd():
    # .NET sample
    # python -m capa.main tests/data/dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_ --json > tests/data/rd/1c444ebeba24dcba8628b7dfe5fec7c6.exe_.json
    return get_result_doc(CD / "data" / "rd" / "1c444ebeba24dcba8628b7dfe5fec7c6.exe_.json")


@pytest.fixture
def a3f3bbc_rd():
    # python -m capa.main tests/data/3f3bbcf8fd90bdcdcdc5494314ed4225.exe_ --json > tests/data/rd/3f3bbcf8fd90bdcdcdc5494314ed4225.exe_.json
    return get_result_doc(CD / "data" / "rd" / "3f3bbcf8fd90bdcdcdc5494314ed4225.exe_.json")


@pytest.fixture
def al_khaserx86_rd():
    # python -m capa.main tests/data/al-khaser_x86.exe_ --json > tests/data/rd/al-khaser_x86.exe_.json
    return get_result_doc(CD / "data" / "rd" / "al-khaser_x86.exe_.json")


@pytest.fixture
def al_khaserx64_rd():
    # python -m capa.main tests/data/al-khaser_x64.exe_ --json > tests/data/rd/al-khaser_x64.exe_.json
    return get_result_doc(CD / "data" / "rd" / "al-khaser_x64.exe_.json")


@pytest.fixture
def a076114_rd():
    # python -m capa.main tests/data/0761142efbda6c4b1e801223de723578.dll_ --json > tests/data/rd/0761142efbda6c4b1e801223de723578.dll_.json
    return get_result_doc(CD / "data" / "rd" / "0761142efbda6c4b1e801223de723578.dll_.json")


@pytest.fixture
def dynamic_a0000a6_rd():
    # python -m capa.main tests/data/dynamic/cape/v2.2/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json --json > tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    # gzip tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    return get_result_doc(
        CD / "data" / "rd" / "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"
    )


PMA1601 = CD / "data" / "Practical Malware Analysis Lab 16-01.exe_"


# used by test_viv_features
# as well as some fixtures below
@functools.lru_cache(maxsize=1)
def get_viv_extractor(path: Path):
    import capa.loader
    import capa.features.extractors.viv.extractor

    sigpaths = [
        CD / "data" / "sigs" / "test_aulldiv.pat",
        CD / "data" / "sigs" / "test_aullrem.pat.gz",
        CD.parent / "sigs" / "1_flare_msvc_rtf_32_64.sig",
        CD.parent / "sigs" / "2_flare_msvc_atlmfc_32_64.sig",
        CD.parent / "sigs" / "3_flare_common_libs.sig",
    ]

    if "raw32" in path.name:
        vw = capa.loader.get_workspace(path, "sc32", sigpaths=sigpaths)
    elif "raw64" in path.name:
        vw = capa.loader.get_workspace(path, "sc64", sigpaths=sigpaths)
    else:
        vw = capa.loader.get_workspace(path, FORMAT_AUTO, sigpaths=sigpaths)
    vw.saveWorkspace()

    extractor = capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, path, OS_AUTO)

    #
    # fixups to overcome differences between backends
    #
    if "3b13b" in path.name:
        # vivisect only recognizes calling thunk function at 0x10001573
        extractor.vw.makeFunction(0x10006860)
    if "294b8d" in path.name:
        # see vivisect/#561
        extractor.vw.makeFunction(0x404970)

    return extractor


@pytest.fixture
def z9324d_extractor():
    return get_viv_extractor(CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_")


@pytest.fixture
def pma16_01_extractor():
    return get_viv_extractor(PMA1601)


@functools.lru_cache(maxsize=1)
def get_pefile_extractor(path: Path):
    import capa.features.extractors.pefile

    extractor = capa.features.extractors.pefile.PefileFeatureExtractor(path)
    setattr(extractor, "path", path.as_posix())
    return extractor


@functools.lru_cache(maxsize=1)
def get_dnfile_extractor(path: Path):
    extractor = DnfileFeatureExtractor(path)
    setattr(extractor, "path", path.as_posix())
    return extractor


@functools.lru_cache(maxsize=1)
def get_dotnetfile_extractor(path: Path):
    import capa.features.extractors.dotnetfile

    extractor = capa.features.extractors.dotnetfile.DotnetFileFeatureExtractor(path)
    setattr(extractor, "path", path.as_posix())
    return extractor


@functools.lru_cache(maxsize=1)
def get_cape_extractor(path):
    from capa.helpers import load_json_from_path
    from capa.features.extractors.cape.extractor import CapeExtractor

    report = load_json_from_path(path)
    return CapeExtractor.from_report(report)


@functools.lru_cache(maxsize=1)
def get_drakvuf_extractor(path):
    from capa.helpers import load_jsonl_from_path
    from capa.features.extractors.drakvuf.extractor import DrakvufExtractor

    report = load_jsonl_from_path(path)
    return DrakvufExtractor.from_report(report)


@functools.lru_cache(maxsize=1)
def get_vmray_extractor(path):
    from capa.features.extractors.vmray.extractor import VMRayExtractor

    return VMRayExtractor.from_zipfile(path)


@functools.lru_cache(maxsize=1)
def get_binja_extractor(path: Path):
    import binaryninja
    from binaryninja import Settings

    import capa.features.extractors.binja.extractor

    settings = Settings()
    if path.name.endswith("kernel32-64.dll_"):
        old_pdb = settings.get_bool("pdb.loadGlobalSymbols")
        settings.set_bool("pdb.loadGlobalSymbols", False)
    else:
        old_pdb = False
    bv = binaryninja.load(str(path))
    if path.name.endswith("kernel32-64.dll_"):
        settings.set_bool("pdb.loadGlobalSymbols", old_pdb)

    if "al-khaser_x64.exe_" in path.name:
        bv.create_user_function(0x14004B4F0)
        bv.update_analysis_and_wait()

    extractor = capa.features.extractors.binja.extractor.BinjaFeatureExtractor(bv)
    setattr(extractor, "path", path.as_posix())
    return extractor


GHIDRA_CACHE: dict[Path, tuple] = {}


def get_ghidra_extractor(path: Path):
    import pyghidra

    if not pyghidra.started():
        pyghidra.start()

    import capa.loader
    import capa.features.extractors.ghidra.context

    if path in GHIDRA_CACHE:
        extractor, program, flat_api, monitor = GHIDRA_CACHE[path]
        capa.features.extractors.ghidra.context.set_context(program, flat_api, monitor)
        return extractor

    extractor = capa.loader.get_extractor(
        path,
        FORMAT_AUTO,
        OS_AUTO,
        capa.loader.BACKEND_GHIDRA,
        [],
        disable_progress=True,
    )

    ctx = capa.features.extractors.ghidra.context.get_context()
    GHIDRA_CACHE[path] = (extractor, ctx.program, ctx.flat_api, ctx.monitor)
    return extractor


def _fixup_idalib(path: Path, extractor):
    import idaapi
    import ida_funcs

    def remove_library_id_flag(fva):
        f = idaapi.get_func(fva)
        f.flags &= ~ida_funcs.FUNC_LIB
        ida_funcs.update_func(f)

    if "kernel32-64" in path.name:
        remove_library_id_flag(0x1800202B0)

    if "al-khaser_x64" in path.name:
        remove_library_id_flag(0x14004B4F0)


IDA_UNPACKED_EXTENSIONS = (".id0", ".id1", ".id2", ".nam", ".til")


def _check_stale_idalib_files(path: Path):
    i64_path = Path(str(path) + ".i64")
    for ext in IDA_UNPACKED_EXTENSIONS:
        component = i64_path.with_suffix(ext)
        if component.exists():
            stale = ", ".join(i64_path.with_suffix(e).name for e in IDA_UNPACKED_EXTENSIONS)
            raise RuntimeError(
                f"stale IDA database component files detected (e.g., {component.name}). "
                f"a previous analysis was likely interrupted. "
                f"remove files like {stale} from {path.parent} before re-running tests."
            )


@contextlib.contextmanager
def get_idalib_extractor(path: Path):
    import shutil
    import tempfile

    import capa.features.extractors.ida.idalib as idalib
    import capa.features.extractors.ida.extractor

    if not idalib.is_idalib_installed():
        raise RuntimeError("idalib is not available.")

    _check_stale_idalib_files(path)

    import idapro
    import ida_auto

    i64_path = Path(str(path) + ".i64")
    had_i64 = i64_path.exists()

    with tempfile.TemporaryDirectory(prefix="capa-idalib-") as tmp:
        tmp_dir = Path(tmp)
        tmp_sample = tmp_dir / path.name
        shutil.copy2(path, tmp_sample)

        if had_i64:
            shutil.copy2(i64_path, tmp_dir / i64_path.name)

        logger.debug("idalib: opening database...")
        idapro.enable_console_messages(False)

        # -R (load resources) is only valid when creating a new database.
        # when reopening an existing .i64, IDA rejects it.
        if had_i64:
            args = "-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0"
        else:
            args = "-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0 -R"

        ret = idapro.open_database(
            str(tmp_sample),
            run_auto_analysis=True,
            args=args,
        )
        if ret != 0:
            raise RuntimeError("failed to analyze input file")

        logger.debug("idalib: waiting for analysis...")
        ida_auto.auto_wait()
        logger.debug("idalib: opened database.")

        extractor = capa.features.extractors.ida.extractor.IdaFeatureExtractor()
        _fixup_idalib(path, extractor)

        try:
            yield extractor
        finally:
            logger.debug("closing database...")
            idapro.close_database(save=(not had_i64))
            logger.debug("closed database.")

@pytest.fixture
def dynamic_a0000a6_rd():
    # python -m capa.main tests/data/dynamic/cape/v2.2/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json --json > tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    # gzip tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    return get_result_doc(
        CD / "data" / "rd" / "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"
    )


@pytest.fixture
def cs_138cdc_extractor_engine():
    with Path(CS_DATA_PATH_BY_NAME["cs_138cdc"]).open("rb") as f:
        buf = f.read()
    return get_ts_extractor_engine(LANG_CS, buf)


@pytest.fixture
def aspx_4f6fa6_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_4f6fa6"])


@pytest.fixture
def aspx_5f959f_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_5f959f"])


@pytest.fixture
def aspx_10162f_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_10162f"])


@pytest.fixture
def aspx_2b71dd_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_2b71dd"])


@pytest.fixture
def aspx_f2bf20_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_f2bf20"])


@pytest.fixture
def aspx_f39dc0_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_f39dc0"])


@pytest.fixture
def aspx_ea2a01_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_ea2a01"])


@pytest.fixture
def aspx_6f3261_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_6f3261"])


@pytest.fixture
def aspx_1f8f40_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_1f8f40"])


@pytest.fixture
def aspx_2e8c7e_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_2e8c7e"])


@pytest.fixture
def aspx_03bb5c_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_03bb5c"])


@pytest.fixture
def aspx_606dbf_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_606dbf"])


@pytest.fixture
def aspx_f397cb_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_f397cb"])


@pytest.fixture
def aspx_b4bb14_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_b4bb14"])


@pytest.fixture
def aspx_54433d_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_54433d"])


@pytest.fixture
def aspx_a35878_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_a35878"])


@pytest.fixture
def aspx_a5c893_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_a5c893"])


@pytest.fixture
def aspx_15eed4_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_15eed4"])


@pytest.fixture
def aspx_b75f16_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_b75f16"])


@pytest.fixture
def aspx_d460ca_template_engine():
    return get_ts_template_engine(ASPX_DATA_PATH_BY_NAME["aspx_d460ca"])


@pytest.fixture
def py_7f9cd1_template_engine():
    return get_ts_extractor_engine(LANG_PY, PY_DATA_PATH_BY_NAME["py_7f9cd1"])


@pytest.fixture
def py_ca0df6_template_engine():
    return get_ts_extractor_engine(LANG_PY, PY_DATA_PATH_BY_NAME["py_ca0df6"])
