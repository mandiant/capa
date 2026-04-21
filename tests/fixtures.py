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
from typing import Union, Literal, Optional
from pathlib import Path
from dataclasses import field, dataclass

import pytest

import capa.rules
import capa.engine as ceng
import capa.loader
import capa.render.result_document
from capa.features.common import OS_AUTO, FORMAT_AUTO, Feature
from capa.features.address import Address
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
FIXTURE_MANIFEST_DIR = CD / "fixtures" / "features"
DOTNET_DIR = CD / "data" / "dotnet"
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
        "symtab",  # requires ELF symbol table parsing  TODO: can we remove this?
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


@contextlib.contextmanager
def xfail(condition, reason: str = ""):
    """
    context manager that wraps a block that is expected to fail in some cases.
    when it does fail (and is expected), then mark this as pytest.xfail.
    if its unexpected, raise an exception, so the test fails.

    example::

        # this test:
        #  - passes on Linux if foo() works
        #  - fails  on Linux if foo() fails
        #  - xfails on Windows if foo() fails
        #  - fails  on Windows if foo() works
        with xfail(sys.platform == "win32", reason="doesn't work on Windows"):
            foo()
    """
    try:
        # do the block
        yield
    except Exception:
        if condition:
            # we expected the test to fail, so raise and register this via pytest
            pytest.xfail(reason or "")
        else:
            # we don't expect an exception, so the test should fail
            raise
    else:
        if not condition:
            # here we expect the block to run successfully,
            # and we've received no exception,
            # so this is good
            pass
        else:
            # we expected an exception, but didn't find one. that's an error.
            raise RuntimeError("expected to fail, but didn't")


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


def get_function(extractor, fva: int) -> FunctionHandle:
    for fh in extractor.get_functions():
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = fh.inner.offset
        else:
            addr = fh.address
        if addr == fva:
            return fh
    raise ValueError("function not found")


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
z9324 = CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_"


# used by test_viv_features
# as well as some fixtures below
@functools.lru_cache(maxsize=1)
def get_viv_extractor(path: Path):
    import capa.main
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
    return get_viv_extractor(z9324)


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

    import capa.features.extractors.ghidra.context
    import capa.features.extractors.ghidra.extractor

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

    if not idalib.has_idalib():
        raise RuntimeError("cannot find IDA idalib module.")

    if not idalib.load_idalib():
        raise RuntimeError("failed to load IDA idalib module.")

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

            if not had_i64:
                tmp_i64 = tmp_dir / i64_path.name
                if tmp_i64.exists():
                    shutil.copy2(tmp_i64, i64_path)


# used by both:
# - test_binexport_features
# - test_binexport_accessors
@functools.lru_cache(maxsize=1)
def get_binexport_extractor(path):
    import capa.features.extractors.binexport2
    import capa.features.extractors.binexport2.extractor

    be2 = capa.features.extractors.binexport2.get_binexport2(path)
    search_paths = [CD / "data", CD / "data" / "aarch64"]
    path = capa.features.extractors.binexport2.get_sample_from_binexport2(path, be2, search_paths)
    buf = path.read_bytes()

    return capa.features.extractors.binexport2.extractor.BinExport2FeatureExtractor(be2, buf)
