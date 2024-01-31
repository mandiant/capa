from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

ADDRESSTYPE_ABSOLUTE: AddressType
ADDRESSTYPE_CALL: AddressType
ADDRESSTYPE_DN_TOKEN: AddressType
ADDRESSTYPE_DN_TOKEN_OFFSET: AddressType
ADDRESSTYPE_FILE: AddressType
ADDRESSTYPE_NO_ADDRESS: AddressType
ADDRESSTYPE_PROCESS: AddressType
ADDRESSTYPE_RELATIVE: AddressType
ADDRESSTYPE_THREAD: AddressType
ADDRESSTYPE_UNSPECIFIED: AddressType
DESCRIPTOR: _descriptor.FileDescriptor
FLAVOR_DYNAMIC: Flavor
FLAVOR_STATIC: Flavor
FLAVOR_UNSPECIFIED: Flavor
SCOPE_BASIC_BLOCK: Scope
SCOPE_CALL: Scope
SCOPE_FILE: Scope
SCOPE_FUNCTION: Scope
SCOPE_INSTRUCTION: Scope
SCOPE_PROCESS: Scope
SCOPE_THREAD: Scope
SCOPE_UNSPECIFIED: Scope

class APIFeature(_message.Message):
    __slots__ = ["api", "description", "type"]
    API_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    api: str
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., api: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Address(_message.Message):
    __slots__ = ["ppid_pid", "ppid_pid_tid", "ppid_pid_tid_id", "token_offset", "type", "v"]
    PPID_PID_FIELD_NUMBER: _ClassVar[int]
    PPID_PID_TID_FIELD_NUMBER: _ClassVar[int]
    PPID_PID_TID_ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_OFFSET_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    V_FIELD_NUMBER: _ClassVar[int]
    ppid_pid: Ppid_Pid
    ppid_pid_tid: Ppid_Pid_Tid
    ppid_pid_tid_id: Ppid_Pid_Tid_Id
    token_offset: Token_Offset
    type: AddressType
    v: Integer
    def __init__(self, type: _Optional[_Union[AddressType, str]] = ..., v: _Optional[_Union[Integer, _Mapping]] = ..., token_offset: _Optional[_Union[Token_Offset, _Mapping]] = ..., ppid_pid: _Optional[_Union[Ppid_Pid, _Mapping]] = ..., ppid_pid_tid: _Optional[_Union[Ppid_Pid_Tid, _Mapping]] = ..., ppid_pid_tid_id: _Optional[_Union[Ppid_Pid_Tid_Id, _Mapping]] = ...) -> None: ...

class Addresses(_message.Message):
    __slots__ = ["address"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: _containers.RepeatedCompositeFieldContainer[Address]
    def __init__(self, address: _Optional[_Iterable[_Union[Address, _Mapping]]] = ...) -> None: ...

class Analysis(_message.Message):
    __slots__ = ["arch", "base_address", "extractor", "feature_counts", "format", "layout", "library_functions", "os", "rules"]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    BASE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    arch: str
    base_address: Address
    extractor: str
    feature_counts: FeatureCounts
    format: str
    layout: Layout
    library_functions: _containers.RepeatedCompositeFieldContainer[LibraryFunction]
    os: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., base_address: _Optional[_Union[Address, _Mapping]] = ..., layout: _Optional[_Union[Layout, _Mapping]] = ..., feature_counts: _Optional[_Union[FeatureCounts, _Mapping]] = ..., library_functions: _Optional[_Iterable[_Union[LibraryFunction, _Mapping]]] = ...) -> None: ...

class ArchFeature(_message.Message):
    __slots__ = ["arch", "description", "type"]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    arch: str
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., arch: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class AttackSpec(_message.Message):
    __slots__ = ["id", "parts", "subtechnique", "tactic", "technique"]
    ID_FIELD_NUMBER: _ClassVar[int]
    PARTS_FIELD_NUMBER: _ClassVar[int]
    SUBTECHNIQUE_FIELD_NUMBER: _ClassVar[int]
    TACTIC_FIELD_NUMBER: _ClassVar[int]
    TECHNIQUE_FIELD_NUMBER: _ClassVar[int]
    id: str
    parts: _containers.RepeatedScalarFieldContainer[str]
    subtechnique: str
    tactic: str
    technique: str
    def __init__(self, parts: _Optional[_Iterable[str]] = ..., tactic: _Optional[str] = ..., technique: _Optional[str] = ..., subtechnique: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class BasicBlockFeature(_message.Message):
    __slots__ = ["description", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class BasicBlockLayout(_message.Message):
    __slots__ = ["address"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ...) -> None: ...

class BytesFeature(_message.Message):
    __slots__ = ["bytes", "description", "type"]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    bytes: str
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., bytes: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class CallLayout(_message.Message):
    __slots__ = ["address", "name"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class CharacteristicFeature(_message.Message):
    __slots__ = ["characteristic", "description", "type"]
    CHARACTERISTIC_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    characteristic: str
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., characteristic: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ClassFeature(_message.Message):
    __slots__ = ["class_", "description", "type"]
    CLASS__FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    class_: str
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., class_: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class CompoundStatement(_message.Message):
    __slots__ = ["description", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class DynamicAnalysis(_message.Message):
    __slots__ = ["arch", "extractor", "feature_counts", "format", "layout", "os", "rules"]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    arch: str
    extractor: str
    feature_counts: DynamicFeatureCounts
    format: str
    layout: DynamicLayout
    os: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., layout: _Optional[_Union[DynamicLayout, _Mapping]] = ..., feature_counts: _Optional[_Union[DynamicFeatureCounts, _Mapping]] = ...) -> None: ...

class DynamicFeatureCounts(_message.Message):
    __slots__ = ["file", "processes"]
    FILE_FIELD_NUMBER: _ClassVar[int]
    PROCESSES_FIELD_NUMBER: _ClassVar[int]
    file: int
    processes: _containers.RepeatedCompositeFieldContainer[ProcessFeatureCount]
    def __init__(self, file: _Optional[int] = ..., processes: _Optional[_Iterable[_Union[ProcessFeatureCount, _Mapping]]] = ...) -> None: ...

class DynamicLayout(_message.Message):
    __slots__ = ["processes"]
    PROCESSES_FIELD_NUMBER: _ClassVar[int]
    processes: _containers.RepeatedCompositeFieldContainer[ProcessLayout]
    def __init__(self, processes: _Optional[_Iterable[_Union[ProcessLayout, _Mapping]]] = ...) -> None: ...

class ExportFeature(_message.Message):
    __slots__ = ["description", "export", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    EXPORT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    export: str
    type: str
    def __init__(self, type: _Optional[str] = ..., export: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class FeatureCounts(_message.Message):
    __slots__ = ["file", "functions"]
    FILE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    file: int
    functions: _containers.RepeatedCompositeFieldContainer[FunctionFeatureCount]
    def __init__(self, file: _Optional[int] = ..., functions: _Optional[_Iterable[_Union[FunctionFeatureCount, _Mapping]]] = ...) -> None: ...

class FeatureNode(_message.Message):
    __slots__ = ["api", "arch", "basic_block", "bytes", "characteristic", "class_", "export", "format", "function_name", "import_", "match", "mnemonic", "namespace", "number", "offset", "operand_number", "operand_offset", "os", "property_", "regex", "section", "string", "substring", "type"]
    API_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    BASIC_BLOCK_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTIC_FIELD_NUMBER: _ClassVar[int]
    CLASS__FIELD_NUMBER: _ClassVar[int]
    EXPORT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    IMPORT__FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    OPERAND_NUMBER_FIELD_NUMBER: _ClassVar[int]
    OPERAND_OFFSET_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    PROPERTY__FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    SECTION_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    SUBSTRING_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    api: APIFeature
    arch: ArchFeature
    basic_block: BasicBlockFeature
    bytes: BytesFeature
    characteristic: CharacteristicFeature
    class_: ClassFeature
    export: ExportFeature
    format: FormatFeature
    function_name: FunctionNameFeature
    import_: ImportFeature
    match: MatchFeature
    mnemonic: MnemonicFeature
    namespace: NamespaceFeature
    number: NumberFeature
    offset: OffsetFeature
    operand_number: OperandNumberFeature
    operand_offset: OperandOffsetFeature
    os: OSFeature
    property_: PropertyFeature
    regex: RegexFeature
    section: SectionFeature
    string: StringFeature
    substring: SubstringFeature
    type: str
    def __init__(self, type: _Optional[str] = ..., os: _Optional[_Union[OSFeature, _Mapping]] = ..., arch: _Optional[_Union[ArchFeature, _Mapping]] = ..., format: _Optional[_Union[FormatFeature, _Mapping]] = ..., match: _Optional[_Union[MatchFeature, _Mapping]] = ..., characteristic: _Optional[_Union[CharacteristicFeature, _Mapping]] = ..., export: _Optional[_Union[ExportFeature, _Mapping]] = ..., import_: _Optional[_Union[ImportFeature, _Mapping]] = ..., section: _Optional[_Union[SectionFeature, _Mapping]] = ..., function_name: _Optional[_Union[FunctionNameFeature, _Mapping]] = ..., substring: _Optional[_Union[SubstringFeature, _Mapping]] = ..., regex: _Optional[_Union[RegexFeature, _Mapping]] = ..., string: _Optional[_Union[StringFeature, _Mapping]] = ..., class_: _Optional[_Union[ClassFeature, _Mapping]] = ..., namespace: _Optional[_Union[NamespaceFeature, _Mapping]] = ..., api: _Optional[_Union[APIFeature, _Mapping]] = ..., property_: _Optional[_Union[PropertyFeature, _Mapping]] = ..., number: _Optional[_Union[NumberFeature, _Mapping]] = ..., bytes: _Optional[_Union[BytesFeature, _Mapping]] = ..., offset: _Optional[_Union[OffsetFeature, _Mapping]] = ..., mnemonic: _Optional[_Union[MnemonicFeature, _Mapping]] = ..., operand_number: _Optional[_Union[OperandNumberFeature, _Mapping]] = ..., operand_offset: _Optional[_Union[OperandOffsetFeature, _Mapping]] = ..., basic_block: _Optional[_Union[BasicBlockFeature, _Mapping]] = ...) -> None: ...

class FormatFeature(_message.Message):
    __slots__ = ["description", "format", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    format: str
    type: str
    def __init__(self, type: _Optional[str] = ..., format: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class FunctionFeatureCount(_message.Message):
    __slots__ = ["address", "count"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    address: Address
    count: int
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., count: _Optional[int] = ...) -> None: ...

class FunctionLayout(_message.Message):
    __slots__ = ["address", "matched_basic_blocks"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_BASIC_BLOCKS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_basic_blocks: _containers.RepeatedCompositeFieldContainer[BasicBlockLayout]
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_basic_blocks: _Optional[_Iterable[_Union[BasicBlockLayout, _Mapping]]] = ...) -> None: ...

class FunctionNameFeature(_message.Message):
    __slots__ = ["description", "function_name", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    function_name: str
    type: str
    def __init__(self, type: _Optional[str] = ..., function_name: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ImportFeature(_message.Message):
    __slots__ = ["description", "import_", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    IMPORT__FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    import_: str
    type: str
    def __init__(self, type: _Optional[str] = ..., import_: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Integer(_message.Message):
    __slots__ = ["i", "u"]
    I_FIELD_NUMBER: _ClassVar[int]
    U_FIELD_NUMBER: _ClassVar[int]
    i: int
    u: int
    def __init__(self, u: _Optional[int] = ..., i: _Optional[int] = ...) -> None: ...

class Layout(_message.Message):
    __slots__ = ["functions"]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    functions: _containers.RepeatedCompositeFieldContainer[FunctionLayout]
    def __init__(self, functions: _Optional[_Iterable[_Union[FunctionLayout, _Mapping]]] = ...) -> None: ...

class LibraryFunction(_message.Message):
    __slots__ = ["address", "name"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class MBCSpec(_message.Message):
    __slots__ = ["behavior", "id", "method", "objective", "parts"]
    BEHAVIOR_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    OBJECTIVE_FIELD_NUMBER: _ClassVar[int]
    PARTS_FIELD_NUMBER: _ClassVar[int]
    behavior: str
    id: str
    method: str
    objective: str
    parts: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, parts: _Optional[_Iterable[str]] = ..., objective: _Optional[str] = ..., behavior: _Optional[str] = ..., method: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class MaecMetadata(_message.Message):
    __slots__ = ["analysis_conclusion", "analysis_conclusion_ov", "malware_category", "malware_category_ov", "malware_family"]
    ANALYSIS_CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_CONCLUSION_OV_FIELD_NUMBER: _ClassVar[int]
    MALWARE_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    MALWARE_CATEGORY_OV_FIELD_NUMBER: _ClassVar[int]
    MALWARE_FAMILY_FIELD_NUMBER: _ClassVar[int]
    analysis_conclusion: str
    analysis_conclusion_ov: str
    malware_category: str
    malware_category_ov: str
    malware_family: str
    def __init__(self, analysis_conclusion: _Optional[str] = ..., analysis_conclusion_ov: _Optional[str] = ..., malware_family: _Optional[str] = ..., malware_category: _Optional[str] = ..., malware_category_ov: _Optional[str] = ...) -> None: ...

class Match(_message.Message):
    __slots__ = ["captures", "children", "feature", "locations", "statement", "success"]
    class CapturesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Addresses
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Addresses, _Mapping]] = ...) -> None: ...
    CAPTURES_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    FEATURE_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_FIELD_NUMBER: _ClassVar[int]
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    captures: _containers.MessageMap[str, Addresses]
    children: _containers.RepeatedCompositeFieldContainer[Match]
    feature: FeatureNode
    locations: _containers.RepeatedCompositeFieldContainer[Address]
    statement: StatementNode
    success: bool
    def __init__(self, success: bool = ..., statement: _Optional[_Union[StatementNode, _Mapping]] = ..., feature: _Optional[_Union[FeatureNode, _Mapping]] = ..., children: _Optional[_Iterable[_Union[Match, _Mapping]]] = ..., locations: _Optional[_Iterable[_Union[Address, _Mapping]]] = ..., captures: _Optional[_Mapping[str, Addresses]] = ...) -> None: ...

class MatchFeature(_message.Message):
    __slots__ = ["description", "match", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    match: str
    type: str
    def __init__(self, type: _Optional[str] = ..., match: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Metadata(_message.Message):
    __slots__ = ["analysis", "argv", "dynamic_analysis", "flavor", "sample", "static_analysis", "timestamp", "version"]
    ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    ARGV_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    FLAVOR_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_FIELD_NUMBER: _ClassVar[int]
    STATIC_ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    analysis: Analysis
    argv: _containers.RepeatedScalarFieldContainer[str]
    dynamic_analysis: DynamicAnalysis
    flavor: Flavor
    sample: Sample
    static_analysis: StaticAnalysis
    timestamp: str
    version: str
    def __init__(self, timestamp: _Optional[str] = ..., version: _Optional[str] = ..., argv: _Optional[_Iterable[str]] = ..., sample: _Optional[_Union[Sample, _Mapping]] = ..., analysis: _Optional[_Union[Analysis, _Mapping]] = ..., flavor: _Optional[_Union[Flavor, str]] = ..., static_analysis: _Optional[_Union[StaticAnalysis, _Mapping]] = ..., dynamic_analysis: _Optional[_Union[DynamicAnalysis, _Mapping]] = ...) -> None: ...

class MnemonicFeature(_message.Message):
    __slots__ = ["description", "mnemonic", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    mnemonic: str
    type: str
    def __init__(self, type: _Optional[str] = ..., mnemonic: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class NamespaceFeature(_message.Message):
    __slots__ = ["description", "namespace", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    namespace: str
    type: str
    def __init__(self, type: _Optional[str] = ..., namespace: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Number(_message.Message):
    __slots__ = ["f", "i", "u"]
    F_FIELD_NUMBER: _ClassVar[int]
    I_FIELD_NUMBER: _ClassVar[int]
    U_FIELD_NUMBER: _ClassVar[int]
    f: float
    i: int
    u: int
    def __init__(self, u: _Optional[int] = ..., i: _Optional[int] = ..., f: _Optional[float] = ...) -> None: ...

class NumberFeature(_message.Message):
    __slots__ = ["description", "number", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    number: Number
    type: str
    def __init__(self, type: _Optional[str] = ..., number: _Optional[_Union[Number, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OSFeature(_message.Message):
    __slots__ = ["description", "os", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    os: str
    type: str
    def __init__(self, type: _Optional[str] = ..., os: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class OffsetFeature(_message.Message):
    __slots__ = ["description", "offset", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    offset: Integer
    type: str
    def __init__(self, type: _Optional[str] = ..., offset: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OperandNumberFeature(_message.Message):
    __slots__ = ["description", "index", "operand_number", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    OPERAND_NUMBER_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    index: int
    operand_number: Integer
    type: str
    def __init__(self, type: _Optional[str] = ..., index: _Optional[int] = ..., operand_number: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OperandOffsetFeature(_message.Message):
    __slots__ = ["description", "index", "operand_offset", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    OPERAND_OFFSET_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    index: int
    operand_offset: Integer
    type: str
    def __init__(self, type: _Optional[str] = ..., index: _Optional[int] = ..., operand_offset: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class Pair_Address_Match(_message.Message):
    __slots__ = ["address", "match"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    address: Address
    match: Match
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., match: _Optional[_Union[Match, _Mapping]] = ...) -> None: ...

class Ppid_Pid(_message.Message):
    __slots__ = ["pid", "ppid"]
    PID_FIELD_NUMBER: _ClassVar[int]
    PPID_FIELD_NUMBER: _ClassVar[int]
    pid: Integer
    ppid: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class Ppid_Pid_Tid(_message.Message):
    __slots__ = ["pid", "ppid", "tid"]
    PID_FIELD_NUMBER: _ClassVar[int]
    PPID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    pid: Integer
    ppid: Integer
    tid: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ..., tid: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class Ppid_Pid_Tid_Id(_message.Message):
    __slots__ = ["id", "pid", "ppid", "tid"]
    ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    PPID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    id: Integer
    pid: Integer
    ppid: Integer
    tid: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ..., tid: _Optional[_Union[Integer, _Mapping]] = ..., id: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class ProcessFeatureCount(_message.Message):
    __slots__ = ["address", "count"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    address: Address
    count: int
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., count: _Optional[int] = ...) -> None: ...

class ProcessLayout(_message.Message):
    __slots__ = ["address", "matched_threads", "name"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_THREADS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_threads: _containers.RepeatedCompositeFieldContainer[ThreadLayout]
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_threads: _Optional[_Iterable[_Union[ThreadLayout, _Mapping]]] = ..., name: _Optional[str] = ...) -> None: ...

class PropertyFeature(_message.Message):
    __slots__ = ["access", "description", "property_", "type"]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PROPERTY__FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    access: str
    description: str
    property_: str
    type: str
    def __init__(self, type: _Optional[str] = ..., property_: _Optional[str] = ..., access: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class RangeStatement(_message.Message):
    __slots__ = ["child", "description", "max", "min", "type"]
    CHILD_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    MIN_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    child: FeatureNode
    description: str
    max: int
    min: int
    type: str
    def __init__(self, type: _Optional[str] = ..., min: _Optional[int] = ..., max: _Optional[int] = ..., child: _Optional[_Union[FeatureNode, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class RegexFeature(_message.Message):
    __slots__ = ["description", "regex", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    regex: str
    type: str
    def __init__(self, type: _Optional[str] = ..., regex: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ResultDocument(_message.Message):
    __slots__ = ["meta", "rules"]
    class RulesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: RuleMatches
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[RuleMatches, _Mapping]] = ...) -> None: ...
    META_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    meta: Metadata
    rules: _containers.MessageMap[str, RuleMatches]
    def __init__(self, meta: _Optional[_Union[Metadata, _Mapping]] = ..., rules: _Optional[_Mapping[str, RuleMatches]] = ...) -> None: ...

class RuleMatches(_message.Message):
    __slots__ = ["matches", "meta", "source"]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    META_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    matches: _containers.RepeatedCompositeFieldContainer[Pair_Address_Match]
    meta: RuleMetadata
    source: str
    def __init__(self, meta: _Optional[_Union[RuleMetadata, _Mapping]] = ..., source: _Optional[str] = ..., matches: _Optional[_Iterable[_Union[Pair_Address_Match, _Mapping]]] = ...) -> None: ...

class RuleMetadata(_message.Message):
    __slots__ = ["attack", "authors", "description", "examples", "is_subscope_rule", "lib", "maec", "mbc", "name", "namespace", "references", "scope", "scopes"]
    ATTACK_FIELD_NUMBER: _ClassVar[int]
    AUTHORS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    EXAMPLES_FIELD_NUMBER: _ClassVar[int]
    IS_SUBSCOPE_RULE_FIELD_NUMBER: _ClassVar[int]
    LIB_FIELD_NUMBER: _ClassVar[int]
    MAEC_FIELD_NUMBER: _ClassVar[int]
    MBC_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    attack: _containers.RepeatedCompositeFieldContainer[AttackSpec]
    authors: _containers.RepeatedScalarFieldContainer[str]
    description: str
    examples: _containers.RepeatedScalarFieldContainer[str]
    is_subscope_rule: bool
    lib: bool
    maec: MaecMetadata
    mbc: _containers.RepeatedCompositeFieldContainer[MBCSpec]
    name: str
    namespace: str
    references: _containers.RepeatedScalarFieldContainer[str]
    scope: Scope
    scopes: Scopes
    def __init__(self, name: _Optional[str] = ..., namespace: _Optional[str] = ..., authors: _Optional[_Iterable[str]] = ..., scope: _Optional[_Union[Scope, str]] = ..., attack: _Optional[_Iterable[_Union[AttackSpec, _Mapping]]] = ..., mbc: _Optional[_Iterable[_Union[MBCSpec, _Mapping]]] = ..., references: _Optional[_Iterable[str]] = ..., examples: _Optional[_Iterable[str]] = ..., description: _Optional[str] = ..., lib: bool = ..., maec: _Optional[_Union[MaecMetadata, _Mapping]] = ..., is_subscope_rule: bool = ..., scopes: _Optional[_Union[Scopes, _Mapping]] = ...) -> None: ...

class Sample(_message.Message):
    __slots__ = ["md5", "path", "sha1", "sha256"]
    MD5_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SHA1_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    md5: str
    path: str
    sha1: str
    sha256: str
    def __init__(self, md5: _Optional[str] = ..., sha1: _Optional[str] = ..., sha256: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class Scopes(_message.Message):
    __slots__ = ["dynamic", "static"]
    DYNAMIC_FIELD_NUMBER: _ClassVar[int]
    STATIC_FIELD_NUMBER: _ClassVar[int]
    dynamic: Scope
    static: Scope
    def __init__(self, static: _Optional[_Union[Scope, str]] = ..., dynamic: _Optional[_Union[Scope, str]] = ...) -> None: ...

class SectionFeature(_message.Message):
    __slots__ = ["description", "section", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SECTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    section: str
    type: str
    def __init__(self, type: _Optional[str] = ..., section: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class SomeStatement(_message.Message):
    __slots__ = ["count", "description", "type"]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    count: int
    description: str
    type: str
    def __init__(self, type: _Optional[str] = ..., count: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class StatementNode(_message.Message):
    __slots__ = ["compound", "range", "some", "subscope", "type"]
    COMPOUND_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SOME_FIELD_NUMBER: _ClassVar[int]
    SUBSCOPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    compound: CompoundStatement
    range: RangeStatement
    some: SomeStatement
    subscope: SubscopeStatement
    type: str
    def __init__(self, type: _Optional[str] = ..., range: _Optional[_Union[RangeStatement, _Mapping]] = ..., some: _Optional[_Union[SomeStatement, _Mapping]] = ..., subscope: _Optional[_Union[SubscopeStatement, _Mapping]] = ..., compound: _Optional[_Union[CompoundStatement, _Mapping]] = ...) -> None: ...

class StaticAnalysis(_message.Message):
    __slots__ = ["arch", "base_address", "extractor", "feature_counts", "format", "layout", "library_functions", "os", "rules"]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    BASE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    arch: str
    base_address: Address
    extractor: str
    feature_counts: StaticFeatureCounts
    format: str
    layout: StaticLayout
    library_functions: _containers.RepeatedCompositeFieldContainer[LibraryFunction]
    os: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., base_address: _Optional[_Union[Address, _Mapping]] = ..., layout: _Optional[_Union[StaticLayout, _Mapping]] = ..., feature_counts: _Optional[_Union[StaticFeatureCounts, _Mapping]] = ..., library_functions: _Optional[_Iterable[_Union[LibraryFunction, _Mapping]]] = ...) -> None: ...

class StaticFeatureCounts(_message.Message):
    __slots__ = ["file", "functions"]
    FILE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    file: int
    functions: _containers.RepeatedCompositeFieldContainer[FunctionFeatureCount]
    def __init__(self, file: _Optional[int] = ..., functions: _Optional[_Iterable[_Union[FunctionFeatureCount, _Mapping]]] = ...) -> None: ...

class StaticLayout(_message.Message):
    __slots__ = ["functions"]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    functions: _containers.RepeatedCompositeFieldContainer[FunctionLayout]
    def __init__(self, functions: _Optional[_Iterable[_Union[FunctionLayout, _Mapping]]] = ...) -> None: ...

class StringFeature(_message.Message):
    __slots__ = ["description", "string", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    string: str
    type: str
    def __init__(self, type: _Optional[str] = ..., string: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class SubscopeStatement(_message.Message):
    __slots__ = ["description", "scope", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    scope: Scope
    type: str
    def __init__(self, type: _Optional[str] = ..., scope: _Optional[_Union[Scope, str]] = ..., description: _Optional[str] = ...) -> None: ...

class SubstringFeature(_message.Message):
    __slots__ = ["description", "substring", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SUBSTRING_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    substring: str
    type: str
    def __init__(self, type: _Optional[str] = ..., substring: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ThreadLayout(_message.Message):
    __slots__ = ["address", "matched_calls"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_CALLS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_calls: _containers.RepeatedCompositeFieldContainer[CallLayout]
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_calls: _Optional[_Iterable[_Union[CallLayout, _Mapping]]] = ...) -> None: ...

class Token_Offset(_message.Message):
    __slots__ = ["offset", "token"]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    offset: int
    token: Integer
    def __init__(self, token: _Optional[_Union[Integer, _Mapping]] = ..., offset: _Optional[int] = ...) -> None: ...

class AddressType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Flavor(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Scope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
