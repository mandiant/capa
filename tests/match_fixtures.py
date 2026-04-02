from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

import capa.rules
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.address
import capa.features.basicblock
import capa.features.extractors.null
from capa.features.common import Feature
from capa.features.address import (
    NO_ADDRESS,
    Address,
    DNTokenAddress,
    ProcessAddress,
    ThreadAddress,
    FileOffsetAddress,
    DynamicCallAddress,
    DNTokenOffsetAddress,
    RelativeVirtualAddress,
    AbsoluteVirtualAddress,
)
from capa.features.extractors.base_extractor import FeatureExtractor, SampleHashes

DUMMY_SAMPLE_HASHES = SampleHashes.from_bytes(b"")
PROCESS_HEADER = re.compile(r"^(?P<name>.+) \(ppid=(?P<ppid>\d+), pid=(?P<pid>\d+)\)$")


@dataclass(frozen=True)
class MatchFixture:
    path: Path
    index: int
    name: str
    description: str
    flavor: str
    ruleset: capa.rules.RuleSet
    extractor: FeatureExtractor
    expected_matches: dict[str, list[Address]]
    span_size: int | None


class StaticFeatureParser:
    def __init__(self, base_address: Address):
        self.base_address = base_address
        self.global_features: list[Feature] = []
        self.file_features: list[tuple[Address, Feature]] = []
        self.functions: dict[
            Address, capa.features.extractors.null.FunctionFeatures
        ] = {}
        self.current_function: Address | None = None
        self.current_basic_block: Address | None = None

    def parse(
        self, source: Any
    ) -> capa.features.extractors.null.NullStaticFeatureExtractor:
        for line in _iter_feature_lines(source):
            self.consume(line)

        return capa.features.extractors.null.NullStaticFeatureExtractor(
            base_address=self.base_address,
            sample_hashes=DUMMY_SAMPLE_HASHES,
            global_features=self.global_features,
            file_features=self.file_features,
            functions=self.functions,
        )

    def consume(self, line: str) -> None:
        if line.startswith("global:"):
            self.consume_global(line)
        elif line.startswith("file:"):
            self.consume_file(line)
        elif line.startswith("func:"):
            self.consume_function(line)
        elif line.startswith("bb:"):
            self.consume_basic_block(line)
        elif line.startswith("insn:"):
            self.consume_instruction(line)
        else:
            raise ValueError(f"unsupported static feature line: {line}")

    def consume_global(self, line: str) -> None:
        rest = _strip_prefix(line, "global:")
        if rest.startswith("global: "):
            rest = rest[len("global: ") :]
        self.global_features.append(_parse_feature(rest))

    def consume_file(self, line: str) -> None:
        addr_text, feature_text, target_text = _split_feature_line(
            _strip_prefix(line, "file:")
        )
        if target_text is not None:
            raise ValueError("file feature lines do not support relocated addresses")
        self.file_features.append(
            (_parse_static_address(addr_text), _parse_feature(feature_text))
        )

    def consume_function(self, line: str) -> None:
        rest = _strip_prefix(line, "func:")
        if ": " not in rest:
            function_address = _parse_static_address(rest)
            self.ensure_function(function_address)
            self.current_function = function_address
            self.current_basic_block = None
            return

        addr_text, feature_text, target_text = _split_feature_line(rest)
        function_address = _parse_static_address(addr_text)
        feature_address = (
            _parse_static_address(target_text)
            if target_text is not None
            else function_address
        )
        self.ensure_function(function_address).features.append(
            (feature_address, _parse_feature(feature_text))
        )
        self.current_function = function_address
        self.current_basic_block = None

    def consume_basic_block(self, line: str) -> None:
        if self.current_function is None:
            raise ValueError(f"basic block line without current function: {line}")

        addr_text, feature_text, target_text = _split_feature_line(
            _strip_prefix(line, "bb:")
        )
        basic_block_address = _parse_static_address(addr_text)
        feature_address = (
            _parse_static_address(target_text)
            if target_text is not None
            else basic_block_address
        )
        self.ensure_basic_block(
            self.current_function, basic_block_address
        ).features.append((feature_address, _parse_feature(feature_text)))
        self.current_basic_block = basic_block_address

    def consume_instruction(self, line: str) -> None:
        if self.current_function is None or self.current_basic_block is None:
            raise ValueError(f"instruction line without current basic block: {line}")

        rest, target_text = _split_target(_strip_prefix(line, "insn:"))
        instruction_address, feature_text = _split_instruction_feature_line(
            rest,
            self.current_function,
            line,
        )

        feature_address = (
            _parse_static_address(target_text)
            if target_text is not None
            else instruction_address
        )
        basic_block = self.ensure_basic_block(
            self.current_function, self.current_basic_block
        )
        instruction = basic_block.instructions.get(instruction_address)
        if instruction is None:
            instruction = capa.features.extractors.null.InstructionFeatures(features=[])
            basic_block.instructions[instruction_address] = instruction
        instruction.features.append((feature_address, _parse_feature(feature_text)))

    def ensure_function(
        self, address: Address
    ) -> capa.features.extractors.null.FunctionFeatures:
        function = self.functions.get(address)
        if function is None:
            function = capa.features.extractors.null.FunctionFeatures(
                features=[], basic_blocks={}
            )
            self.functions[address] = function
        return function

    def ensure_basic_block(
        self, function_address: Address, basic_block_address: Address
    ) -> capa.features.extractors.null.BasicBlockFeatures:
        function = self.ensure_function(function_address)
        basic_block = function.basic_blocks.get(basic_block_address)
        if basic_block is None:
            basic_block = capa.features.extractors.null.BasicBlockFeatures(
                features=[], instructions={}
            )
            function.basic_blocks[basic_block_address] = basic_block
        return basic_block


class DynamicFeatureParser:
    def __init__(self):
        self.global_features: list[Feature] = []
        self.file_features: list[tuple[Address, Feature]] = []
        self.processes: dict[
            Address, capa.features.extractors.null.ProcessFeatures
        ] = {}
        self.calls_by_id: dict[int, DynamicCallAddress] = {}
        self.current_process: ProcessAddress | None = None
        self.current_thread: ThreadAddress | None = None

    def parse(
        self, source: Any
    ) -> capa.features.extractors.null.NullDynamicFeatureExtractor:
        for line in _iter_feature_lines(source):
            self.consume(line)

        return capa.features.extractors.null.NullDynamicFeatureExtractor(
            base_address=NO_ADDRESS,
            sample_hashes=DUMMY_SAMPLE_HASHES,
            global_features=self.global_features,
            file_features=self.file_features,
            processes=self.processes,
        )

    def consume(self, line: str) -> None:
        if line.startswith("global:"):
            self.consume_global(line)
        elif line.startswith("file:"):
            self.consume_file(line)
        elif line.startswith("proc:"):
            self.consume_process(line)
        elif line.startswith("thread:"):
            self.consume_thread(line)
        elif line.startswith("call:"):
            self.consume_call(line)
        else:
            raise ValueError(f"unsupported dynamic feature line: {line}")

    def consume_global(self, line: str) -> None:
        rest = _strip_prefix(line, "global:")
        if rest.startswith("global: "):
            rest = rest[len("global: ") :]
        self.global_features.append(_parse_feature(rest))

    def consume_file(self, line: str) -> None:
        addr_text, feature_text, target_text = _split_feature_line(
            _strip_prefix(line, "file:")
        )
        if target_text is not None:
            raise ValueError("file feature lines do not support relocated addresses")
        self.file_features.append(
            (_parse_address(addr_text), _parse_feature(feature_text))
        )

    def consume_process(self, line: str) -> None:
        rest = _strip_prefix(line, "proc:")
        header = PROCESS_HEADER.fullmatch(rest)
        if header is not None:
            process_address = ProcessAddress(
                ppid=int(header.group("ppid")), pid=int(header.group("pid"))
            )
            self.ensure_process(process_address, header.group("name"))
            self.current_process = process_address
            self.current_thread = None
            return

        if self.current_process is None:
            raise ValueError(f"process feature line without current process: {line}")

        name, feature_text, target_text = _split_feature_line(rest)
        process = self.ensure_process(self.current_process)
        if process.name != name:
            raise ValueError(
                f"process feature line does not match current process: {line}"
            )
        feature_address = (
            _parse_address(target_text)
            if target_text is not None
            else self.current_process
        )
        process.features.append((feature_address, _parse_feature(feature_text)))

    def consume_thread(self, line: str) -> None:
        if self.current_process is None:
            raise ValueError(f"thread line without current process: {line}")

        rest = _strip_prefix(line, "thread:")
        if ": " not in rest:
            thread_address = ThreadAddress(
                process=self.current_process, tid=int(rest, 0)
            )
            self.ensure_thread(thread_address)
            self.current_thread = thread_address
            return

        tid_text, feature_text, target_text = _split_feature_line(rest)
        thread_address = ThreadAddress(
            process=self.current_process, tid=int(tid_text, 0)
        )
        thread = self.ensure_thread(thread_address)
        feature_address = (
            _parse_address(target_text) if target_text is not None else thread_address
        )
        thread.features.append((feature_address, _parse_feature(feature_text)))
        self.current_thread = thread_address

    def consume_call(self, line: str) -> None:
        if self.current_thread is None:
            raise ValueError(f"call line without current thread: {line}")

        call_id_text, feature_text, target_text = _split_feature_line(
            _strip_prefix(line, "call:")
        )
        call_address = DynamicCallAddress(
            thread=self.current_thread, id=int(call_id_text, 0)
        )
        call = self.ensure_call(call_address)
        feature_address = (
            _parse_address(target_text) if target_text is not None else call_address
        )
        call.features.append((feature_address, _parse_feature(feature_text)))

    def ensure_process(
        self, address: ProcessAddress, name: str | None = None
    ) -> capa.features.extractors.null.ProcessFeatures:
        process = self.processes.get(address)
        if process is None:
            process = capa.features.extractors.null.ProcessFeatures(
                name=name or f"process-{address.pid}",
                features=[],
                threads={},
            )
            self.processes[address] = process
        elif name is not None:
            process.name = name
        return process

    def ensure_thread(
        self, address: ThreadAddress
    ) -> capa.features.extractors.null.ThreadFeatures:
        process = self.ensure_process(address.process)
        thread = process.threads.get(address)
        if thread is None:
            thread = capa.features.extractors.null.ThreadFeatures(features=[], calls={})
            process.threads[address] = thread
        return thread

    def ensure_call(
        self, address: DynamicCallAddress
    ) -> capa.features.extractors.null.CallFeatures:
        existing = self.calls_by_id.get(address.id)
        if existing is not None and existing != address:
            raise ValueError(
                f"dynamic fixture call IDs must be unique within a test: {address.id}"
            )

        self.calls_by_id[address.id] = address

        thread = self.ensure_thread(address.thread)
        call = thread.calls.get(address)
        if call is None:
            call = capa.features.extractors.null.CallFeatures(
                name=f"call-{address.id}", features=[]
            )
            thread.calls[address] = call
        return call


def load_fixtures(path: Path) -> list[MatchFixture]:
    doc = yaml.safe_load(path.read_text())
    fixture_docs = _get_fixture_docs(path, doc)
    fixtures: list[MatchFixture] = []

    for index, fixture_doc in enumerate(fixture_docs, start=1):
        flavor = _get_fixture_flavor(path, fixture_doc)
        span_size = _load_span_size(fixture_doc)

        if flavor == "static":
            static_parser = StaticFeatureParser(
                _parse_static_address(fixture_doc.get("base address", 0))
            )
            extractor = static_parser.parse(fixture_doc.get("features", ""))
            expected_matches = _load_expected_matches(fixture_doc, flavor)
        elif flavor == "dynamic":
            dynamic_parser = DynamicFeatureParser()
            extractor = dynamic_parser.parse(fixture_doc.get("features", ""))
            expected_matches = _load_expected_matches(
                fixture_doc,
                flavor,
                dynamic_parser=dynamic_parser,
            )
        else:
            raise ValueError(f"unsupported fixture flavor: {flavor}")

        ruleset = _load_ruleset(path, fixture_doc, flavor)

        fixtures.append(
            MatchFixture(
                path=path,
                index=index,
                name=str(fixture_doc.get("name", f"{path.stem}-{index}")),
                description=str(fixture_doc.get("description", "")),
                flavor=flavor,
                ruleset=ruleset,
                extractor=extractor,
                expected_matches=expected_matches,
                span_size=span_size,
            )
        )

    return fixtures


def load_fixture(path: Path) -> MatchFixture:
    fixtures = load_fixtures(path)
    if len(fixtures) != 1:
        raise ValueError(f"fixture file contains {len(fixtures)} tests: {path}")
    return fixtures[0]


def render_matches(
    fixture: MatchFixture, matches: dict[str, Any]
) -> dict[str, list[Address]]:
    return {
        rule_name: [address for address, _ in results]
        for rule_name, results in matches.items()
        if rule_name in fixture.ruleset
        and not fixture.ruleset[rule_name].is_subscope_rule()
    }


def _get_fixture_docs(path: Path, doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        fixture_docs = doc
    elif isinstance(doc, dict) and isinstance(doc.get("tests"), list):
        fixture_docs = doc["tests"]
    elif isinstance(doc, dict):
        fixture_docs = [doc]
    else:
        raise ValueError(f"fixture file must contain a mapping or list: {path}")

    for fixture_doc in fixture_docs:
        if not isinstance(fixture_doc, dict):
            raise ValueError(f"fixture test must be a mapping: {path}")

    return fixture_docs


def _get_fixture_flavor(path: Path, doc: dict[str, Any]) -> str:
    explicit = doc.get("flavor")
    inferred = next(
        (part for part in reversed(path.parts) if part in {"static", "dynamic"}),
        None,
    )

    if explicit is None:
        if inferred is None:
            raise ValueError(f"fixture flavor could not be inferred from path: {path}")
        return inferred

    if not isinstance(explicit, str):
        raise ValueError("fixture flavor must be a string")

    if inferred is not None and explicit != inferred:
        raise ValueError(
            f"fixture flavor {explicit!r} does not match file location {inferred!r}: {path}"
        )

    return explicit


def _normalize_rule_doc(rule_doc: dict[str, Any], flavor: str) -> dict[str, Any]:
    meta = rule_doc.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("rule meta must be a mapping")

    scopes = meta.setdefault("scopes", {})
    if not isinstance(scopes, dict):
        raise ValueError("rule scopes must be a mapping")

    if flavor == "static":
        scopes.setdefault("dynamic", "unsupported")
    elif flavor == "dynamic":
        scopes.setdefault("static", "unsupported")

    return rule_doc


def _load_ruleset(path: Path, doc: dict[str, Any], flavor: str) -> capa.rules.RuleSet:
    rules: list[capa.rules.Rule] = []
    for rule_doc in doc.get("rules", []):
        if not isinstance(rule_doc, dict):
            raise ValueError(f"rule must be a mapping: {path}")
        wrapped = {"rule": _normalize_rule_doc(rule_doc, flavor)}
        definition = yaml.safe_dump(wrapped, sort_keys=False)
        rules.append(capa.rules.Rule.from_dict(wrapped, definition))
    return capa.rules.RuleSet(rules)


def _load_expected_matches(
    doc: dict[str, Any],
    flavor: str,
    dynamic_parser: DynamicFeatureParser | None = None,
) -> dict[str, list[Address]]:
    expect = doc.get("expect", {})
    if not isinstance(expect, dict):
        raise ValueError("fixture expect must be a mapping")

    matches = expect.get("matches", {})
    if not isinstance(matches, dict):
        raise ValueError("fixture expect.matches must be a mapping")

    return {
        rule_name: [
            _parse_expected_address(spec, flavor, dynamic_parser) for spec in locations
        ]
        for rule_name, locations in matches.items()
    }


def _parse_expected_address(
    spec: Any,
    flavor: str,
    dynamic_parser: DynamicFeatureParser | None = None,
) -> Address:
    if flavor == "dynamic" and dynamic_parser is not None:
        if isinstance(spec, int) and spec in dynamic_parser.calls_by_id:
            return dynamic_parser.calls_by_id[spec]

        if isinstance(spec, str):
            call_id = re.fullmatch(r"call\((\d+)\)", spec)
            if call_id is not None:
                call_address = dynamic_parser.calls_by_id.get(int(call_id.group(1)))
                if call_address is None:
                    raise ValueError(f"unknown dynamic fixture call ID: {spec}")
                return call_address

    return _parse_address(spec)


def _load_span_size(doc: dict[str, Any]) -> int | None:
    options = doc.get("options", {})
    if not isinstance(options, dict):
        raise ValueError("fixture options must be a mapping")

    span_size = options.get("span size")
    if span_size is None:
        return None
    if not isinstance(span_size, int):
        raise ValueError("fixture options.span size must be an integer")
    return span_size


def _iter_feature_lines(source: Any) -> Iterable[str]:
    if isinstance(source, str):
        lines = source.splitlines()
    elif isinstance(source, list):
        lines = source
    else:
        raise ValueError("fixture features must be a block string or list of strings")

    for line in lines:
        if not isinstance(line, str):
            raise ValueError("fixture feature lines must be strings")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        yield stripped


def _split_feature_line(text: str) -> tuple[str, str, str | None]:
    body, target = _split_target(text)
    scope_text, separator, feature_text = body.partition(": ")
    if not separator:
        raise ValueError(f"expected '<scope>: <feature>': {text}")
    return scope_text, feature_text, target


def _split_instruction_feature_line(
    text: str,
    current_function: Address,
    line: str,
) -> tuple[Address, str]:
    addr1_text, separator, remainder = text.partition(": ")
    if not separator:
        raise ValueError(f"unsupported instruction feature line: {line}")

    addr2_text, separator, feature_text = remainder.partition(": ")
    if separator:
        try:
            function_address = _parse_static_address(addr1_text)
            instruction_address = _parse_static_address(addr2_text)
        except ValueError:
            return _parse_static_address(addr1_text), remainder

        if function_address != current_function:
            raise ValueError(
                f"instruction line changed function without a function header: {line}"
            )

        return instruction_address, feature_text

    return _parse_static_address(addr1_text), remainder


def _split_target(text: str) -> tuple[str, str | None]:
    if " -> " not in text:
        return text, None
    return text.rsplit(" -> ", 1)


def _parse_feature(text: str) -> Feature:
    text = text.strip()
    if text == "basic block":
        return capa.features.basicblock.BasicBlock()

    operand_number = re.fullmatch(r"operand\[(\d+)\]\.number\((.*)\)", text)
    if operand_number:
        return capa.features.insn.OperandNumber(
            int(operand_number.group(1)),
            _parse_number_literal(operand_number.group(2)),
        )

    operand_offset = re.fullmatch(r"operand\[(\d+)\]\.offset\((.*)\)", text)
    if operand_offset:
        return capa.features.insn.OperandOffset(
            int(operand_offset.group(1)),
            _parse_int_literal(operand_offset.group(2)),
        )

    property_ = re.fullmatch(r"property(?:/(read|write))?\((.*)\)", text)
    if property_:
        return capa.features.insn.Property(
            _strip_quotes(property_.group(2).strip()),
            access=property_.group(1),
        )

    feature = re.fullmatch(r"([a-z][a-z0-9\- ]*)\((.*)\)", text)
    if feature is None:
        raise ValueError(f"unsupported feature syntax: {text}")

    name = feature.group(1)
    value = _strip_quotes(feature.group(2).strip())

    if name == "api":
        return capa.features.insn.API(value)
    if name == "arch":
        return capa.features.common.Arch(value)
    if name == "bytes":
        return capa.features.common.Bytes(bytes.fromhex(value.replace(" ", "")))
    if name == "characteristic":
        return capa.features.common.Characteristic(value)
    if name == "class":
        return capa.features.common.Class(value)
    if name == "export":
        return capa.features.file.Export(value)
    if name == "format":
        return capa.features.common.Format(value)
    if name in ("function-name", "function name"):
        return capa.features.file.FunctionName(value)
    if name == "import":
        return capa.features.file.Import(value)
    if name == "match":
        return capa.features.common.MatchedRule(value)
    if name == "mnemonic":
        return capa.features.insn.Mnemonic(value)
    if name == "namespace":
        return capa.features.common.Namespace(value)
    if name == "number":
        return capa.features.insn.Number(_parse_number_literal(value))
    if name == "offset":
        return capa.features.insn.Offset(_parse_int_literal(value))
    if name == "os":
        return capa.features.common.OS(value)
    if name == "section":
        return capa.features.file.Section(value)
    if name == "string":
        return capa.features.common.String(value)
    if name == "substring":
        return capa.features.common.Substring(value)

    raise ValueError(f"unsupported feature type: {name}")


def _parse_number_literal(value: str) -> int | float:
    value = value.strip()
    if _looks_like_hex_literal(value):
        return int(value, 0)
    if any(character in value for character in ".eE"):
        return float(value)
    return int(value, 0)


def _looks_like_hex_literal(value: str) -> bool:
    return value.lstrip("+-").lower().startswith("0x")


def _parse_int_literal(value: str) -> int:
    return int(value, 0)


def _parse_static_address(spec: Any) -> Address:
    address = _parse_address(spec)
    if isinstance(address, (ProcessAddress, ThreadAddress, DynamicCallAddress)):
        raise ValueError(f"expected a static address, got {spec!r}")
    return address


def _parse_address(spec: Any) -> Address:
    if spec is None:
        return NO_ADDRESS

    if isinstance(spec, int):
        return AbsoluteVirtualAddress(spec)

    if isinstance(spec, list):
        if not spec:
            raise ValueError(f"unsupported address: {spec!r}")

        kind = spec[0]
        if kind == "absolute":
            return AbsoluteVirtualAddress(_coerce_int(spec[1]))
        if kind == "relative":
            return RelativeVirtualAddress(_coerce_int(spec[1]))
        if kind == "file":
            return FileOffsetAddress(_coerce_int(spec[1]))
        if kind == "token":
            return DNTokenAddress(_coerce_int(spec[1]))
        if kind == "token offset":
            return DNTokenOffsetAddress(_coerce_int(spec[1]), _coerce_int(spec[2]))
        if kind == "process":
            return ProcessAddress(ppid=int(spec[1]), pid=int(spec[2]))
        if kind == "thread":
            return ThreadAddress(
                process=ProcessAddress(ppid=int(spec[1]), pid=int(spec[2])),
                tid=int(spec[3]),
            )
        if kind == "call":
            return DynamicCallAddress(
                thread=ThreadAddress(
                    process=ProcessAddress(ppid=int(spec[1]), pid=int(spec[2])),
                    tid=int(spec[3]),
                ),
                id=int(spec[4]),
            )
        if kind == "no address":
            return NO_ADDRESS
        raise ValueError(f"unsupported address type: {kind}")

    if not isinstance(spec, str):
        raise ValueError(f"unsupported address: {spec!r}")

    if spec in {"global", "no address"}:
        return NO_ADDRESS
    if spec.startswith("base address+"):
        return RelativeVirtualAddress(_coerce_int(spec[len("base address+") :]))
    if spec.startswith("file+"):
        return FileOffsetAddress(_coerce_int(spec[len("file+") :]))
    if token_offset := re.fullmatch(r"token\((.+)\)\+(.+)", spec):
        return DNTokenOffsetAddress(
            _coerce_int(token_offset.group(1)), _coerce_int(token_offset.group(2))
        )
    if token := re.fullmatch(r"token\((.+)\)", spec):
        return DNTokenAddress(_coerce_int(token.group(1)))
    if process := re.fullmatch(r"process\{ppid:(\d+),pid:(\d+)\}", spec):
        return ProcessAddress(ppid=int(process.group(1)), pid=int(process.group(2)))
    if process := re.fullmatch(r"process\{pid:(\d+)\}", spec):
        return ProcessAddress(pid=int(process.group(1)))
    if thread := re.fullmatch(r"process\{ppid:(\d+),pid:(\d+),tid:(\d+)\}", spec):
        return ThreadAddress(
            process=ProcessAddress(ppid=int(thread.group(1)), pid=int(thread.group(2))),
            tid=int(thread.group(3)),
        )
    if thread := re.fullmatch(r"process\{pid:(\d+),tid:(\d+)\}", spec):
        return ThreadAddress(
            process=ProcessAddress(pid=int(thread.group(1))), tid=int(thread.group(2))
        )
    if call := re.fullmatch(
        r"process\{ppid:(\d+),pid:(\d+),tid:(\d+),call:(\d+)\}", spec
    ):
        return DynamicCallAddress(
            thread=ThreadAddress(
                process=ProcessAddress(ppid=int(call.group(1)), pid=int(call.group(2))),
                tid=int(call.group(3)),
            ),
            id=int(call.group(4)),
        )
    if call := re.fullmatch(r"process\{pid:(\d+),tid:(\d+),call:(\d+)\}", spec):
        return DynamicCallAddress(
            thread=ThreadAddress(
                process=ProcessAddress(pid=int(call.group(1))), tid=int(call.group(2))
            ),
            id=int(call.group(3)),
        )
    return AbsoluteVirtualAddress(_coerce_int(spec))


def _coerce_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer value: {value!r}")


def _require_string(doc: dict[str, Any], key: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str):
        raise ValueError(f"expected string for {key}")
    return value


def _strip_prefix(text: str, prefix: str) -> str:
    return text[len(prefix) :].strip()


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
