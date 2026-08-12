from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AddressType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ADDRESSTYPE_UNSPECIFIED: _ClassVar[AddressType]
    ADDRESSTYPE_ABSOLUTE: _ClassVar[AddressType]
    ADDRESSTYPE_RELATIVE: _ClassVar[AddressType]
    ADDRESSTYPE_FILE: _ClassVar[AddressType]
    ADDRESSTYPE_DN_TOKEN: _ClassVar[AddressType]
    ADDRESSTYPE_DN_TOKEN_OFFSET: _ClassVar[AddressType]
    ADDRESSTYPE_NO_ADDRESS: _ClassVar[AddressType]
    ADDRESSTYPE_PROCESS: _ClassVar[AddressType]
    ADDRESSTYPE_THREAD: _ClassVar[AddressType]
    ADDRESSTYPE_CALL: _ClassVar[AddressType]
    ADDRESSTYPE_FILE_RANGE: _ClassVar[AddressType]

class Flavor(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FLAVOR_UNSPECIFIED: _ClassVar[Flavor]
    FLAVOR_STATIC: _ClassVar[Flavor]
    FLAVOR_DYNAMIC: _ClassVar[Flavor]

class Scope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCOPE_UNSPECIFIED: _ClassVar[Scope]
    SCOPE_FILE: _ClassVar[Scope]
    SCOPE_FUNCTION: _ClassVar[Scope]
    SCOPE_BASIC_BLOCK: _ClassVar[Scope]
    SCOPE_INSTRUCTION: _ClassVar[Scope]
    SCOPE_PROCESS: _ClassVar[Scope]
    SCOPE_THREAD: _ClassVar[Scope]
    SCOPE_CALL: _ClassVar[Scope]
    SCOPE_SPAN_OF_CALLS: _ClassVar[Scope]
ADDRESSTYPE_UNSPECIFIED: AddressType
ADDRESSTYPE_ABSOLUTE: AddressType
ADDRESSTYPE_RELATIVE: AddressType
ADDRESSTYPE_FILE: AddressType
ADDRESSTYPE_DN_TOKEN: AddressType
ADDRESSTYPE_DN_TOKEN_OFFSET: AddressType
ADDRESSTYPE_NO_ADDRESS: AddressType
ADDRESSTYPE_PROCESS: AddressType
ADDRESSTYPE_THREAD: AddressType
ADDRESSTYPE_CALL: AddressType
ADDRESSTYPE_FILE_RANGE: AddressType
FLAVOR_UNSPECIFIED: Flavor
FLAVOR_STATIC: Flavor
FLAVOR_DYNAMIC: Flavor
SCOPE_UNSPECIFIED: Scope
SCOPE_FILE: Scope
SCOPE_FUNCTION: Scope
SCOPE_BASIC_BLOCK: Scope
SCOPE_INSTRUCTION: Scope
SCOPE_PROCESS: Scope
SCOPE_THREAD: Scope
SCOPE_CALL: Scope
SCOPE_SPAN_OF_CALLS: Scope

class APIFeature(_message.Message):
    __slots__ = ("type", "api", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    API_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    api: str
    description: str
    def __init__(self, type: _Optional[str] = ..., api: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Address(_message.Message):
    __slots__ = ("type", "v", "token_offset", "ppid_pid", "ppid_pid_tid", "ppid_pid_tid_id", "file_range")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    V_FIELD_NUMBER: _ClassVar[int]
    TOKEN_OFFSET_FIELD_NUMBER: _ClassVar[int]
    PPID_PID_FIELD_NUMBER: _ClassVar[int]
    PPID_PID_TID_FIELD_NUMBER: _ClassVar[int]
    PPID_PID_TID_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_RANGE_FIELD_NUMBER: _ClassVar[int]
    type: AddressType
    v: Integer
    token_offset: Token_Offset
    ppid_pid: Ppid_Pid
    ppid_pid_tid: Ppid_Pid_Tid
    ppid_pid_tid_id: Ppid_Pid_Tid_Id
    file_range: FileOffsetRange
    def __init__(self, type: _Optional[_Union[AddressType, str]] = ..., v: _Optional[_Union[Integer, _Mapping]] = ..., token_offset: _Optional[_Union[Token_Offset, _Mapping]] = ..., ppid_pid: _Optional[_Union[Ppid_Pid, _Mapping]] = ..., ppid_pid_tid: _Optional[_Union[Ppid_Pid_Tid, _Mapping]] = ..., ppid_pid_tid_id: _Optional[_Union[Ppid_Pid_Tid_Id, _Mapping]] = ..., file_range: _Optional[_Union[FileOffsetRange, _Mapping]] = ...) -> None: ...

class Analysis(_message.Message):
    __slots__ = ("format", "arch", "os", "extractor", "rules", "base_address", "layout", "feature_counts", "library_functions")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    BASE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    format: str
    arch: str
    os: str
    extractor: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    base_address: Address
    layout: Layout
    feature_counts: FeatureCounts
    library_functions: _containers.RepeatedCompositeFieldContainer[LibraryFunction]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., base_address: _Optional[_Union[Address, _Mapping]] = ..., layout: _Optional[_Union[Layout, _Mapping]] = ..., feature_counts: _Optional[_Union[FeatureCounts, _Mapping]] = ..., library_functions: _Optional[_Iterable[_Union[LibraryFunction, _Mapping]]] = ...) -> None: ...

class ArchFeature(_message.Message):
    __slots__ = ("type", "arch", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    arch: str
    description: str
    def __init__(self, type: _Optional[str] = ..., arch: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class AttackSpec(_message.Message):
    __slots__ = ("parts", "tactic", "technique", "subtechnique", "id")
    PARTS_FIELD_NUMBER: _ClassVar[int]
    TACTIC_FIELD_NUMBER: _ClassVar[int]
    TECHNIQUE_FIELD_NUMBER: _ClassVar[int]
    SUBTECHNIQUE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    parts: _containers.RepeatedScalarFieldContainer[str]
    tactic: str
    technique: str
    subtechnique: str
    id: str
    def __init__(self, parts: _Optional[_Iterable[str]] = ..., tactic: _Optional[str] = ..., technique: _Optional[str] = ..., subtechnique: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class BasicBlockFeature(_message.Message):
    __slots__ = ("type", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    description: str
    def __init__(self, type: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class BasicBlockLayout(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ...) -> None: ...

class BytesFeature(_message.Message):
    __slots__ = ("type", "bytes", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    bytes: str
    description: str
    def __init__(self, type: _Optional[str] = ..., bytes: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class CharacteristicFeature(_message.Message):
    __slots__ = ("type", "characteristic", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTIC_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    characteristic: str
    description: str
    def __init__(self, type: _Optional[str] = ..., characteristic: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ClassFeature(_message.Message):
    __slots__ = ("type", "class_", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CLASS__FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    class_: str
    description: str
    def __init__(self, type: _Optional[str] = ..., class_: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class CompoundStatement(_message.Message):
    __slots__ = ("type", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    description: str
    def __init__(self, type: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class DynamicAnalysis(_message.Message):
    __slots__ = ("format", "arch", "os", "extractor", "rules", "layout", "feature_counts")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    format: str
    arch: str
    os: str
    extractor: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    layout: DynamicLayout
    feature_counts: DynamicFeatureCounts
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., layout: _Optional[_Union[DynamicLayout, _Mapping]] = ..., feature_counts: _Optional[_Union[DynamicFeatureCounts, _Mapping]] = ...) -> None: ...

class DynamicFeatureCounts(_message.Message):
    __slots__ = ("file", "processes")
    FILE_FIELD_NUMBER: _ClassVar[int]
    PROCESSES_FIELD_NUMBER: _ClassVar[int]
    file: int
    processes: _containers.RepeatedCompositeFieldContainer[ProcessFeatureCount]
    def __init__(self, file: _Optional[int] = ..., processes: _Optional[_Iterable[_Union[ProcessFeatureCount, _Mapping]]] = ...) -> None: ...

class DynamicLayout(_message.Message):
    __slots__ = ("processes",)
    PROCESSES_FIELD_NUMBER: _ClassVar[int]
    processes: _containers.RepeatedCompositeFieldContainer[ProcessLayout]
    def __init__(self, processes: _Optional[_Iterable[_Union[ProcessLayout, _Mapping]]] = ...) -> None: ...

class ExportFeature(_message.Message):
    __slots__ = ("type", "export", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    EXPORT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    export: str
    description: str
    def __init__(self, type: _Optional[str] = ..., export: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class FeatureCounts(_message.Message):
    __slots__ = ("file", "functions")
    FILE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    file: int
    functions: _containers.RepeatedCompositeFieldContainer[FunctionFeatureCount]
    def __init__(self, file: _Optional[int] = ..., functions: _Optional[_Iterable[_Union[FunctionFeatureCount, _Mapping]]] = ...) -> None: ...

class FeatureNode(_message.Message):
    __slots__ = ("type", "os", "arch", "format", "match", "characteristic", "export", "import_", "section", "function_name", "substring", "regex", "string", "class_", "namespace", "api", "property_", "number", "bytes", "offset", "mnemonic", "operand_number", "operand_offset", "basic_block", "script_language")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    CHARACTERISTIC_FIELD_NUMBER: _ClassVar[int]
    EXPORT_FIELD_NUMBER: _ClassVar[int]
    IMPORT__FIELD_NUMBER: _ClassVar[int]
    SECTION_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    SUBSTRING_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    CLASS__FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    API_FIELD_NUMBER: _ClassVar[int]
    PROPERTY__FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    OPERAND_NUMBER_FIELD_NUMBER: _ClassVar[int]
    OPERAND_OFFSET_FIELD_NUMBER: _ClassVar[int]
    BASIC_BLOCK_FIELD_NUMBER: _ClassVar[int]
    SCRIPT_LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    type: str
    os: OSFeature
    arch: ArchFeature
    format: FormatFeature
    match: MatchFeature
    characteristic: CharacteristicFeature
    export: ExportFeature
    import_: ImportFeature
    section: SectionFeature
    function_name: FunctionNameFeature
    substring: SubstringFeature
    regex: RegexFeature
    string: StringFeature
    class_: ClassFeature
    namespace: NamespaceFeature
    api: APIFeature
    property_: PropertyFeature
    number: NumberFeature
    bytes: BytesFeature
    offset: OffsetFeature
    mnemonic: MnemonicFeature
    operand_number: OperandNumberFeature
    operand_offset: OperandOffsetFeature
    basic_block: BasicBlockFeature
    script_language: ScriptLanguageFeature
    def __init__(self, type: _Optional[str] = ..., os: _Optional[_Union[OSFeature, _Mapping]] = ..., arch: _Optional[_Union[ArchFeature, _Mapping]] = ..., format: _Optional[_Union[FormatFeature, _Mapping]] = ..., match: _Optional[_Union[MatchFeature, _Mapping]] = ..., characteristic: _Optional[_Union[CharacteristicFeature, _Mapping]] = ..., export: _Optional[_Union[ExportFeature, _Mapping]] = ..., import_: _Optional[_Union[ImportFeature, _Mapping]] = ..., section: _Optional[_Union[SectionFeature, _Mapping]] = ..., function_name: _Optional[_Union[FunctionNameFeature, _Mapping]] = ..., substring: _Optional[_Union[SubstringFeature, _Mapping]] = ..., regex: _Optional[_Union[RegexFeature, _Mapping]] = ..., string: _Optional[_Union[StringFeature, _Mapping]] = ..., class_: _Optional[_Union[ClassFeature, _Mapping]] = ..., namespace: _Optional[_Union[NamespaceFeature, _Mapping]] = ..., api: _Optional[_Union[APIFeature, _Mapping]] = ..., property_: _Optional[_Union[PropertyFeature, _Mapping]] = ..., number: _Optional[_Union[NumberFeature, _Mapping]] = ..., bytes: _Optional[_Union[BytesFeature, _Mapping]] = ..., offset: _Optional[_Union[OffsetFeature, _Mapping]] = ..., mnemonic: _Optional[_Union[MnemonicFeature, _Mapping]] = ..., operand_number: _Optional[_Union[OperandNumberFeature, _Mapping]] = ..., operand_offset: _Optional[_Union[OperandOffsetFeature, _Mapping]] = ..., basic_block: _Optional[_Union[BasicBlockFeature, _Mapping]] = ..., script_language: _Optional[_Union[ScriptLanguageFeature, _Mapping]] = ...) -> None: ...

class FormatFeature(_message.Message):
    __slots__ = ("type", "format", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    format: str
    description: str
    def __init__(self, type: _Optional[str] = ..., format: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class FunctionFeatureCount(_message.Message):
    __slots__ = ("address", "count")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    address: Address
    count: int
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., count: _Optional[int] = ...) -> None: ...

class FunctionLayout(_message.Message):
    __slots__ = ("address", "matched_basic_blocks")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_BASIC_BLOCKS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_basic_blocks: _containers.RepeatedCompositeFieldContainer[BasicBlockLayout]
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_basic_blocks: _Optional[_Iterable[_Union[BasicBlockLayout, _Mapping]]] = ...) -> None: ...

class FunctionNameFeature(_message.Message):
    __slots__ = ("type", "function_name", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    function_name: str
    description: str
    def __init__(self, type: _Optional[str] = ..., function_name: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ImportFeature(_message.Message):
    __slots__ = ("type", "import_", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    IMPORT__FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    import_: str
    description: str
    def __init__(self, type: _Optional[str] = ..., import_: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Layout(_message.Message):
    __slots__ = ("functions",)
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    functions: _containers.RepeatedCompositeFieldContainer[FunctionLayout]
    def __init__(self, functions: _Optional[_Iterable[_Union[FunctionLayout, _Mapping]]] = ...) -> None: ...

class LibraryFunction(_message.Message):
    __slots__ = ("address", "name")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class MBCSpec(_message.Message):
    __slots__ = ("parts", "objective", "behavior", "method", "id")
    PARTS_FIELD_NUMBER: _ClassVar[int]
    OBJECTIVE_FIELD_NUMBER: _ClassVar[int]
    BEHAVIOR_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    parts: _containers.RepeatedScalarFieldContainer[str]
    objective: str
    behavior: str
    method: str
    id: str
    def __init__(self, parts: _Optional[_Iterable[str]] = ..., objective: _Optional[str] = ..., behavior: _Optional[str] = ..., method: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class MaecMetadata(_message.Message):
    __slots__ = ("analysis_conclusion", "analysis_conclusion_ov", "malware_family", "malware_category", "malware_category_ov")
    ANALYSIS_CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_CONCLUSION_OV_FIELD_NUMBER: _ClassVar[int]
    MALWARE_FAMILY_FIELD_NUMBER: _ClassVar[int]
    MALWARE_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    MALWARE_CATEGORY_OV_FIELD_NUMBER: _ClassVar[int]
    analysis_conclusion: str
    analysis_conclusion_ov: str
    malware_family: str
    malware_category: str
    malware_category_ov: str
    def __init__(self, analysis_conclusion: _Optional[str] = ..., analysis_conclusion_ov: _Optional[str] = ..., malware_family: _Optional[str] = ..., malware_category: _Optional[str] = ..., malware_category_ov: _Optional[str] = ...) -> None: ...

class Match(_message.Message):
    __slots__ = ("success", "statement", "feature", "children", "locations", "captures")
    class CapturesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Addresses
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Addresses, _Mapping]] = ...) -> None: ...
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    FEATURE_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_FIELD_NUMBER: _ClassVar[int]
    CAPTURES_FIELD_NUMBER: _ClassVar[int]
    success: bool
    statement: StatementNode
    feature: FeatureNode
    children: _containers.RepeatedCompositeFieldContainer[Match]
    locations: _containers.RepeatedCompositeFieldContainer[Address]
    captures: _containers.MessageMap[str, Addresses]
    def __init__(self, success: bool = ..., statement: _Optional[_Union[StatementNode, _Mapping]] = ..., feature: _Optional[_Union[FeatureNode, _Mapping]] = ..., children: _Optional[_Iterable[_Union[Match, _Mapping]]] = ..., locations: _Optional[_Iterable[_Union[Address, _Mapping]]] = ..., captures: _Optional[_Mapping[str, Addresses]] = ...) -> None: ...

class MatchFeature(_message.Message):
    __slots__ = ("type", "match", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    match: str
    description: str
    def __init__(self, type: _Optional[str] = ..., match: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Metadata(_message.Message):
    __slots__ = ("timestamp", "version", "argv", "sample", "analysis", "flavor", "static_analysis", "dynamic_analysis")
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ARGV_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    FLAVOR_FIELD_NUMBER: _ClassVar[int]
    STATIC_ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_ANALYSIS_FIELD_NUMBER: _ClassVar[int]
    timestamp: str
    version: str
    argv: _containers.RepeatedScalarFieldContainer[str]
    sample: Sample
    analysis: Analysis
    flavor: Flavor
    static_analysis: StaticAnalysis
    dynamic_analysis: DynamicAnalysis
    def __init__(self, timestamp: _Optional[str] = ..., version: _Optional[str] = ..., argv: _Optional[_Iterable[str]] = ..., sample: _Optional[_Union[Sample, _Mapping]] = ..., analysis: _Optional[_Union[Analysis, _Mapping]] = ..., flavor: _Optional[_Union[Flavor, str]] = ..., static_analysis: _Optional[_Union[StaticAnalysis, _Mapping]] = ..., dynamic_analysis: _Optional[_Union[DynamicAnalysis, _Mapping]] = ...) -> None: ...

class MnemonicFeature(_message.Message):
    __slots__ = ("type", "mnemonic", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MNEMONIC_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    mnemonic: str
    description: str
    def __init__(self, type: _Optional[str] = ..., mnemonic: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class NamespaceFeature(_message.Message):
    __slots__ = ("type", "namespace", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    namespace: str
    description: str
    def __init__(self, type: _Optional[str] = ..., namespace: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class NumberFeature(_message.Message):
    __slots__ = ("type", "number", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    number: Number
    description: str
    def __init__(self, type: _Optional[str] = ..., number: _Optional[_Union[Number, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OSFeature(_message.Message):
    __slots__ = ("type", "os", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    os: str
    description: str
    def __init__(self, type: _Optional[str] = ..., os: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class OffsetFeature(_message.Message):
    __slots__ = ("type", "offset", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    offset: Integer
    description: str
    def __init__(self, type: _Optional[str] = ..., offset: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OperandNumberFeature(_message.Message):
    __slots__ = ("type", "index", "operand_number", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    OPERAND_NUMBER_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    index: int
    operand_number: Integer
    description: str
    def __init__(self, type: _Optional[str] = ..., index: _Optional[int] = ..., operand_number: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class OperandOffsetFeature(_message.Message):
    __slots__ = ("type", "index", "operand_offset", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    OPERAND_OFFSET_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    index: int
    operand_offset: Integer
    description: str
    def __init__(self, type: _Optional[str] = ..., index: _Optional[int] = ..., operand_offset: _Optional[_Union[Integer, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class ProcessFeatureCount(_message.Message):
    __slots__ = ("address", "count")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    address: Address
    count: int
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., count: _Optional[int] = ...) -> None: ...

class ProcessLayout(_message.Message):
    __slots__ = ("address", "matched_threads", "name")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_THREADS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_threads: _containers.RepeatedCompositeFieldContainer[ThreadLayout]
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_threads: _Optional[_Iterable[_Union[ThreadLayout, _Mapping]]] = ..., name: _Optional[str] = ...) -> None: ...

class PropertyFeature(_message.Message):
    __slots__ = ("type", "property_", "access", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    PROPERTY__FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    property_: str
    access: str
    description: str
    def __init__(self, type: _Optional[str] = ..., property_: _Optional[str] = ..., access: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class RangeStatement(_message.Message):
    __slots__ = ("type", "min", "max", "child", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MIN_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    CHILD_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    min: int
    max: int
    child: FeatureNode
    description: str
    def __init__(self, type: _Optional[str] = ..., min: _Optional[int] = ..., max: _Optional[int] = ..., child: _Optional[_Union[FeatureNode, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class RegexFeature(_message.Message):
    __slots__ = ("type", "regex", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REGEX_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    regex: str
    description: str
    def __init__(self, type: _Optional[str] = ..., regex: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class ResultDocument(_message.Message):
    __slots__ = ("meta", "rules")
    class RulesEntry(_message.Message):
        __slots__ = ("key", "value")
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
    __slots__ = ("meta", "source", "matches")
    META_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    meta: RuleMetadata
    source: str
    matches: _containers.RepeatedCompositeFieldContainer[Pair_Address_Match]
    def __init__(self, meta: _Optional[_Union[RuleMetadata, _Mapping]] = ..., source: _Optional[str] = ..., matches: _Optional[_Iterable[_Union[Pair_Address_Match, _Mapping]]] = ...) -> None: ...

class RuleMetadata(_message.Message):
    __slots__ = ("name", "namespace", "authors", "scope", "attack", "mbc", "references", "examples", "description", "lib", "maec", "is_subscope_rule", "scopes")
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    AUTHORS_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    ATTACK_FIELD_NUMBER: _ClassVar[int]
    MBC_FIELD_NUMBER: _ClassVar[int]
    REFERENCES_FIELD_NUMBER: _ClassVar[int]
    EXAMPLES_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LIB_FIELD_NUMBER: _ClassVar[int]
    MAEC_FIELD_NUMBER: _ClassVar[int]
    IS_SUBSCOPE_RULE_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    name: str
    namespace: str
    authors: _containers.RepeatedScalarFieldContainer[str]
    scope: Scope
    attack: _containers.RepeatedCompositeFieldContainer[AttackSpec]
    mbc: _containers.RepeatedCompositeFieldContainer[MBCSpec]
    references: _containers.RepeatedScalarFieldContainer[str]
    examples: _containers.RepeatedScalarFieldContainer[str]
    description: str
    lib: bool
    maec: MaecMetadata
    is_subscope_rule: bool
    scopes: Scopes
    def __init__(self, name: _Optional[str] = ..., namespace: _Optional[str] = ..., authors: _Optional[_Iterable[str]] = ..., scope: _Optional[_Union[Scope, str]] = ..., attack: _Optional[_Iterable[_Union[AttackSpec, _Mapping]]] = ..., mbc: _Optional[_Iterable[_Union[MBCSpec, _Mapping]]] = ..., references: _Optional[_Iterable[str]] = ..., examples: _Optional[_Iterable[str]] = ..., description: _Optional[str] = ..., lib: bool = ..., maec: _Optional[_Union[MaecMetadata, _Mapping]] = ..., is_subscope_rule: bool = ..., scopes: _Optional[_Union[Scopes, _Mapping]] = ...) -> None: ...

class Sample(_message.Message):
    __slots__ = ("md5", "sha1", "sha256", "path")
    MD5_FIELD_NUMBER: _ClassVar[int]
    SHA1_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    md5: str
    sha1: str
    sha256: str
    path: str
    def __init__(self, md5: _Optional[str] = ..., sha1: _Optional[str] = ..., sha256: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class Scopes(_message.Message):
    __slots__ = ("static", "dynamic")
    STATIC_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_FIELD_NUMBER: _ClassVar[int]
    static: Scope
    dynamic: Scope
    def __init__(self, static: _Optional[_Union[Scope, str]] = ..., dynamic: _Optional[_Union[Scope, str]] = ...) -> None: ...

class SectionFeature(_message.Message):
    __slots__ = ("type", "section", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SECTION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    section: str
    description: str
    def __init__(self, type: _Optional[str] = ..., section: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class SomeStatement(_message.Message):
    __slots__ = ("type", "count", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    count: int
    description: str
    def __init__(self, type: _Optional[str] = ..., count: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class StatementNode(_message.Message):
    __slots__ = ("type", "range", "some", "subscope", "compound")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SOME_FIELD_NUMBER: _ClassVar[int]
    SUBSCOPE_FIELD_NUMBER: _ClassVar[int]
    COMPOUND_FIELD_NUMBER: _ClassVar[int]
    type: str
    range: RangeStatement
    some: SomeStatement
    subscope: SubscopeStatement
    compound: CompoundStatement
    def __init__(self, type: _Optional[str] = ..., range: _Optional[_Union[RangeStatement, _Mapping]] = ..., some: _Optional[_Union[SomeStatement, _Mapping]] = ..., subscope: _Optional[_Union[SubscopeStatement, _Mapping]] = ..., compound: _Optional[_Union[CompoundStatement, _Mapping]] = ...) -> None: ...

class StaticAnalysis(_message.Message):
    __slots__ = ("format", "arch", "os", "extractor", "rules", "base_address", "layout", "feature_counts", "library_functions")
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    EXTRACTOR_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    BASE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_FIELD_NUMBER: _ClassVar[int]
    FEATURE_COUNTS_FIELD_NUMBER: _ClassVar[int]
    LIBRARY_FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    format: str
    arch: str
    os: str
    extractor: str
    rules: _containers.RepeatedScalarFieldContainer[str]
    base_address: Address
    layout: StaticLayout
    feature_counts: StaticFeatureCounts
    library_functions: _containers.RepeatedCompositeFieldContainer[LibraryFunction]
    def __init__(self, format: _Optional[str] = ..., arch: _Optional[str] = ..., os: _Optional[str] = ..., extractor: _Optional[str] = ..., rules: _Optional[_Iterable[str]] = ..., base_address: _Optional[_Union[Address, _Mapping]] = ..., layout: _Optional[_Union[StaticLayout, _Mapping]] = ..., feature_counts: _Optional[_Union[StaticFeatureCounts, _Mapping]] = ..., library_functions: _Optional[_Iterable[_Union[LibraryFunction, _Mapping]]] = ...) -> None: ...

class StaticFeatureCounts(_message.Message):
    __slots__ = ("file", "functions")
    FILE_FIELD_NUMBER: _ClassVar[int]
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    file: int
    functions: _containers.RepeatedCompositeFieldContainer[FunctionFeatureCount]
    def __init__(self, file: _Optional[int] = ..., functions: _Optional[_Iterable[_Union[FunctionFeatureCount, _Mapping]]] = ...) -> None: ...

class StaticLayout(_message.Message):
    __slots__ = ("functions",)
    FUNCTIONS_FIELD_NUMBER: _ClassVar[int]
    functions: _containers.RepeatedCompositeFieldContainer[FunctionLayout]
    def __init__(self, functions: _Optional[_Iterable[_Union[FunctionLayout, _Mapping]]] = ...) -> None: ...

class StringFeature(_message.Message):
    __slots__ = ("type", "string", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    string: str
    description: str
    def __init__(self, type: _Optional[str] = ..., string: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class SubscopeStatement(_message.Message):
    __slots__ = ("type", "scope", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    scope: Scope
    description: str
    def __init__(self, type: _Optional[str] = ..., scope: _Optional[_Union[Scope, str]] = ..., description: _Optional[str] = ...) -> None: ...

class SubstringFeature(_message.Message):
    __slots__ = ("type", "substring", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SUBSTRING_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    substring: str
    description: str
    def __init__(self, type: _Optional[str] = ..., substring: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class CallLayout(_message.Message):
    __slots__ = ("address", "name")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    address: Address
    name: str
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class ThreadLayout(_message.Message):
    __slots__ = ("address", "matched_calls")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCHED_CALLS_FIELD_NUMBER: _ClassVar[int]
    address: Address
    matched_calls: _containers.RepeatedCompositeFieldContainer[CallLayout]
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., matched_calls: _Optional[_Iterable[_Union[CallLayout, _Mapping]]] = ...) -> None: ...

class Addresses(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: _containers.RepeatedCompositeFieldContainer[Address]
    def __init__(self, address: _Optional[_Iterable[_Union[Address, _Mapping]]] = ...) -> None: ...

class Pair_Address_Match(_message.Message):
    __slots__ = ("address", "match")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MATCH_FIELD_NUMBER: _ClassVar[int]
    address: Address
    match: Match
    def __init__(self, address: _Optional[_Union[Address, _Mapping]] = ..., match: _Optional[_Union[Match, _Mapping]] = ...) -> None: ...

class Token_Offset(_message.Message):
    __slots__ = ("token", "offset")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    token: Integer
    offset: int
    def __init__(self, token: _Optional[_Union[Integer, _Mapping]] = ..., offset: _Optional[int] = ...) -> None: ...

class Ppid_Pid(_message.Message):
    __slots__ = ("ppid", "pid")
    PPID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    ppid: Integer
    pid: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class Ppid_Pid_Tid(_message.Message):
    __slots__ = ("ppid", "pid", "tid")
    PPID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ppid: Integer
    pid: Integer
    tid: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ..., tid: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class Ppid_Pid_Tid_Id(_message.Message):
    __slots__ = ("ppid", "pid", "tid", "id")
    PPID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    ppid: Integer
    pid: Integer
    tid: Integer
    id: Integer
    def __init__(self, ppid: _Optional[_Union[Integer, _Mapping]] = ..., pid: _Optional[_Union[Integer, _Mapping]] = ..., tid: _Optional[_Union[Integer, _Mapping]] = ..., id: _Optional[_Union[Integer, _Mapping]] = ...) -> None: ...

class Integer(_message.Message):
    __slots__ = ("u", "i")
    U_FIELD_NUMBER: _ClassVar[int]
    I_FIELD_NUMBER: _ClassVar[int]
    u: int
    i: int
    def __init__(self, u: _Optional[int] = ..., i: _Optional[int] = ...) -> None: ...

class Number(_message.Message):
    __slots__ = ("u", "i", "f")
    U_FIELD_NUMBER: _ClassVar[int]
    I_FIELD_NUMBER: _ClassVar[int]
    F_FIELD_NUMBER: _ClassVar[int]
    u: int
    i: int
    f: float
    def __init__(self, u: _Optional[int] = ..., i: _Optional[int] = ..., f: _Optional[float] = ...) -> None: ...

class FileOffsetRange(_message.Message):
    __slots__ = ("start", "end")
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    start: int
    end: int
    def __init__(self, start: _Optional[int] = ..., end: _Optional[int] = ...) -> None: ...

class ScriptLanguageFeature(_message.Message):
    __slots__ = ("type", "language", "description")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    type: str
    language: str
    description: str
    def __init__(self, type: _Optional[str] = ..., language: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...
