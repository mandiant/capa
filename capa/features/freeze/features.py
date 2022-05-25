import binascii
from typing import Any, Union

from pydantic import Field, BaseModel

import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock


class FeatureModel(BaseModel):
    class Config:
        frozen = True
        allow_population_by_field_name = True

    def to_capa(self) -> capa.features.common.Feature:
        if isinstance(self, OSFeature):
            return capa.features.common.OS(self.os)

        elif isinstance(self, ArchFeature):
            return capa.features.common.Arch(self.arch)

        elif isinstance(self, FormatFeature):
            return capa.features.common.Format(self.format)

        elif isinstance(self, MatchedRuleFeature):
            return capa.features.common.MatchedRule(self.match)

        elif isinstance(
            self,
            CharacteristicFeature,
        ):
            return capa.features.common.Characteristic(self.characteristic)

        elif isinstance(self, ExportFeature):
            return capa.features.file.Export(self.export)

        elif isinstance(self, ImportFeature):
            return capa.features.file.Import(self.import_)

        elif isinstance(self, SectionFeature):
            return capa.features.file.Section(self.section)

        elif isinstance(self, FunctionNameFeature):
            return capa.features.file.FunctionName(self.function_name)

        elif isinstance(self, StringFeature):
            return capa.features.common.String(self.string)

        elif isinstance(self, BasicBlockFeature):
            return capa.features.basicblock.BasicBlock()

        elif isinstance(self, APIFeature):
            return capa.features.insn.API(self.api)

        elif isinstance(self, NumberFeature):
            return capa.features.insn.Number(self.number)

        elif isinstance(self, BytesFeature):
            return capa.features.common.Bytes(binascii.unhexlify(self.bytes))

        elif isinstance(self, OffsetFeature):
            return capa.features.insn.Offset(self.offset)

        elif isinstance(self, MnemonicFeature):
            return capa.features.insn.Mnemonic(self.mnemonic)

        elif isinstance(self, OperandNumberFeature):
            return capa.features.insn.OperandNumber(
                self.index,
                self.operand_number,
            )

        elif isinstance(self, OperandOffsetFeature):
            return capa.features.insn.OperandOffset(
                self.index,
                self.operand_offset,
            )

        else:
            raise NotImplementedError(f"Feature.to_capa({type(self)}) not implemented")


def feature_from_capa(f: capa.features.common.Feature) -> "Feature":
    if isinstance(f, capa.features.common.OS):
        return OSFeature(os=f.value)

    elif isinstance(f, capa.features.common.Arch):
        return ArchFeature(arch=f.value)

    elif isinstance(f, capa.features.common.Format):
        return FormatFeature(format=f.value)

    elif isinstance(f, capa.features.common.MatchedRule):
        return MatchedRuleFeature(match=f.value)

    elif isinstance(f, capa.features.common.Characteristic):
        return CharacteristicFeature(characteristic=f.value)

    elif isinstance(f, capa.features.file.Export):
        return ExportFeature(export=f.value)

    elif isinstance(f, capa.features.file.Import):
        return ImportFeature(import_=f.value)

    elif isinstance(f, capa.features.file.Section):
        return SectionFeature(section=f.value)

    elif isinstance(f, capa.features.file.FunctionName):
        return FunctionNameFeature(function_name=f.value)

    elif isinstance(f, capa.features.common.String):
        return StringFeature(string=f.value)

    elif isinstance(f, capa.features.basicblock.BasicBlock):
        return BasicBlockFeature()

    elif isinstance(f, capa.features.insn.API):
        return APIFeature(api=f.value)

    elif isinstance(f, capa.features.insn.Number):
        return NumberFeature(number=f.value)

    elif isinstance(f, capa.features.common.Bytes):
        buf = f.value
        assert isinstance(buf, bytes)
        return BytesFeature(bytes=binascii.hexlify(buf).decode("ascii"))

    elif isinstance(f, capa.features.insn.Offset):
        return OffsetFeature(offset=f.value)

    elif isinstance(f, capa.features.insn.Mnemonic):
        return MnemonicFeature(mnemonic=f.value)

    elif isinstance(f, capa.features.insn.OperandNumber):
        return OperandNumberFeature(index=f.index, operand_number=f.value)

    elif isinstance(f, capa.features.insn.OperandOffset):
        return OperandOffsetFeature(index=f.index, operand_offset=f.value)

    else:
        raise NotImplementedError(f"feature_from_capa({type(f)}) not implemented")


class OSFeature(FeatureModel):
    type: str = "os"
    os: str


class ArchFeature(FeatureModel):
    type: str = "arch"
    arch: str


class FormatFeature(FeatureModel):
    type: str = "format"
    format: str


class MatchedRuleFeature(FeatureModel):
    type: str = "match"
    match: str


class CharacteristicFeature(FeatureModel):
    type: str = "characteristic"
    characteristic: str


class ExportFeature(FeatureModel):
    type: str = "export"
    export: str


class ImportFeature(FeatureModel):
    type: str = "import"
    import_: str = Field(alias="import")


class SectionFeature(FeatureModel):
    type: str = "section"
    section: str


class FunctionNameFeature(FeatureModel):
    type: str = "function name"
    function_name: str = Field(alias="function name")


class StringFeature(FeatureModel):
    type: str = "string"
    string: str


class BasicBlockFeature(FeatureModel):
    type: str = "basic block"


class APIFeature(FeatureModel):
    type: str = "api"
    api: str


class NumberFeature(FeatureModel):
    type: str = "number"
    number: Union[int, float]


class BytesFeature(FeatureModel):
    type: str = "bytes"
    bytes: str


class OffsetFeature(FeatureModel):
    type: str = "offset"
    offset: int


class MnemonicFeature(FeatureModel):
    type: str = "mnemonic"
    mnemonic: str


class OperandNumberFeature(FeatureModel):
    type: str = "operand number"
    index: int
    operand_number: int = Field(alias="operand number")


class OperandOffsetFeature(FeatureModel):
    type: str = "operand offset"
    index: int
    operand_offset: int = Field(alias="operand offset")


Feature = Union[
    OSFeature,
    ArchFeature,
    FormatFeature,
    MatchedRuleFeature,
    CharacteristicFeature,
    ExportFeature,
    ImportFeature,
    SectionFeature,
    FunctionNameFeature,
    StringFeature,
    APIFeature,
    NumberFeature,
    BytesFeature,
    OffsetFeature,
    MnemonicFeature,
    OperandNumberFeature,
    OperandOffsetFeature,
    # this has to go last because...? pydantic fails to serialize correctly otherwise.
    # possibly because this feature has no associated value?
    BasicBlockFeature,
]
