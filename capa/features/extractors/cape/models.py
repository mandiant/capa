# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import binascii
from typing import Any, Dict, List, Union, Literal, Optional

from pydantic import Field, BaseModel, ConfigDict
from typing_extensions import Annotated, TypeAlias
from pydantic.functional_validators import BeforeValidator


def validate_hex_int(value):
    return int(value, 16) if isinstance(value, str) else value


def validate_hex_bytes(value):
    return binascii.unhexlify(value) if isinstance(value, str) else value


HexInt = Annotated[int, BeforeValidator(validate_hex_int)]
HexBytes = Annotated[bytes, BeforeValidator(validate_hex_bytes)]


# a model that *cannot* have extra fields
# if they do, pydantic raises an exception.
# use this for models we rely upon and cannot change.
#
# for things that may be extended and we don't care,
# use FlexibleModel.
class ExactModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# a model that can have extra fields that we ignore.
# use this if we don't want to raise an exception for extra
# data fields that we didn't expect.
class FlexibleModel(BaseModel):
    pass


# use this type to indicate that we won't model this data.
# because its not relevant to our use in capa.
#
# while its nice to have full coverage of the data shape,
# it can easily change and break our parsing.
# so we really only want to describe what we'll use.
Skip: TypeAlias = Optional[Any]


# mark fields that we haven't seen yet and need to model.
# pydantic should raise an error when encountering data
# in a field with this type.
# then we can update the model with the discovered shape.
TODO: TypeAlias = None
ListTODO: TypeAlias = List[None]
DictTODO: TypeAlias = ExactModel

EmptyDict: TypeAlias = BaseModel
EmptyList: TypeAlias = List[Any]


class ImportedSymbol(ExactModel):
    address: HexInt
    name: str


class ImportedDll(ExactModel):
    dll: str
    imports: List[ImportedSymbol]


class DirectoryEntry(ExactModel):
    name: str
    virtual_address: HexInt
    size: HexInt


class Section(ExactModel):
    name: str
    raw_address: HexInt
    virtual_address: HexInt
    virtual_size: HexInt
    size_of_data: HexInt
    characteristics: str
    characteristics_raw: HexInt
    entropy: float


class Resource(ExactModel):
    name: str
    language: Optional[str] = None
    sublanguage: str
    filetype: Optional[str]
    offset: HexInt
    size: HexInt
    entropy: float


class DigitalSigner(FlexibleModel):
    extensions_authorityInfoAccess_caIssuers: Optional[str] = None
    extensions_authorityKeyIdentifier: Optional[str] = None
    extensions_cRLDistributionPoints_0: Optional[str] = None
    extensions_certificatePolicies_0: Optional[str] = None
    extensions_subjectAltName_0: Optional[str] = None
    extensions_subjectKeyIdentifier: Optional[str] = None

    issuer_commonName: str
    issuer_countryName: str
    issuer_localityName: str
    issuer_organizationName: str
    issuer_stateOrProvinceName: str
    md5_fingerprint: str
    not_after: str
    not_before: str
    serial_number: str
    sha1_fingerprint: str
    sha256_fingerprint: str
    subject_commonName: str
    subject_countryName: str
    subject_localityName: str
    subject_organizationName: str
    subject_stateOrProvinceName: str


class Signer(ExactModel):
    aux_sha1: Optional[TODO] = None
    aux_timestamp: Optional[None] = None
    aux_valid: Optional[bool] = None
    aux_error: Optional[bool] = None
    aux_error_desc: Optional[str] = None
    aux_signers: Optional[ListTODO] = None


class Overlay(ExactModel):
    offset: HexInt
    size: HexInt


class KV(ExactModel):
    name: str
    value: str


class ExportedSymbol(ExactModel):
    address: HexInt
    name: str
    ordinal: int


class PE(ExactModel):
    peid_signatures: TODO
    imagebase: HexInt
    entrypoint: HexInt
    reported_checksum: HexInt
    actual_checksum: HexInt
    osversion: str
    pdbpath: Optional[str] = None
    timestamp: str

    # List[ImportedDll], or Dict[basename(dll), ImportedDll]
    imports: Union[List[ImportedDll], Dict[str, ImportedDll]]
    imported_dll_count: Optional[int] = None
    imphash: str

    exported_dll_name: Optional[str] = None
    exports: List[ExportedSymbol]

    dirents: List[DirectoryEntry]
    sections: List[Section]

    ep_bytes: Optional[HexBytes] = None

    overlay: Optional[Overlay] = None
    resources: List[Resource]
    versioninfo: List[KV]

    # base64 encoded data
    icon: Optional[str] = None
    # MD5-like hash
    icon_hash: Optional[str] = None
    # MD5-like hash
    icon_fuzzy: Optional[str] = None
    # short hex string
    icon_dhash: Optional[str] = None

    digital_signers: List[DigitalSigner]
    guest_signers: Signer


class File(ExactModel):
    type: str
    cape_type_code: Optional[int] = None
    cape_type: Optional[str] = None

    pid: Optional[Union[int, Literal[""]]] = None
    name: Union[List[str], str]
    path: str
    guest_paths: Union[List[str], str, None]
    timestamp: Optional[str] = None

    #
    # hashes
    #
    crc32: str
    md5: str
    sha1: str
    sha256: str
    sha512: str
    sha3_384: str
    ssdeep: str
    tlsh: Optional[str] = None
    rh_hash: Optional[str] = None

    #
    # other metadata, static analysis
    #
    size: int
    pe: Optional[PE] = None
    ep_bytes: Optional[HexBytes] = None
    entrypoint: Optional[int] = None
    data: Optional[str] = None
    strings: Optional[List[str]] = None

    #
    # detections (skip)
    #
    yara: Skip = None
    cape_yara: Skip = None
    clamav: Skip = None
    virustotal: Skip = None


class ProcessFile(File):
    #
    # like a File, but also has dynamic analysis results
    #
    pid: int
    process_path: str
    process_name: str
    module_path: str
    virtual_address: Optional[HexInt] = None
    target_pid: Optional[int] = None
    target_path: Optional[str] = None
    target_process: Optional[str] = None


class Argument(ExactModel):
    name: str
    # unsure why empty list is provided here
    value: Union[HexInt, str, EmptyList]
    pretty_value: Optional[str] = None


class Call(ExactModel):
    timestamp: str
    thread_id: int
    category: str

    api: str

    arguments: List[Argument]
    status: bool
    return_: HexInt = Field(alias="return")
    pretty_return: Optional[str] = None

    repeated: int

    # virtual addresses
    caller: HexInt
    parentcaller: HexInt

    # index into calls array
    id: int


class Process(ExactModel):
    process_id: int
    process_name: str
    parent_id: int
    module_path: str
    first_seen: str
    calls: List[Call]
    threads: List[int]
    environ: Dict[str, str]


class ProcessTree(ExactModel):
    name: str
    pid: int
    parent_id: int
    module_path: str
    threads: List[int]
    environ: Dict[str, str]
    children: List["ProcessTree"]


class Summary(ExactModel):
    files: List[str]
    read_files: List[str]
    write_files: List[str]
    delete_files: List[str]
    keys: List[str]
    read_keys: List[str]
    write_keys: List[str]
    delete_keys: List[str]
    executed_commands: List[str]
    resolved_apis: List[str]
    mutexes: List[str]
    created_services: List[str]
    started_services: List[str]


class EncryptedBuffer(ExactModel):
    process_name: str
    pid: int

    api_call: str
    buffer: str
    buffer_size: int


class Behavior(ExactModel):
    summary: Summary

    # list of processes, of threads, of calls
    processes: List[Process]
    # tree of processes
    processtree: List[ProcessTree]

    anomaly: List[str]
    encryptedbuffers: List[EncryptedBuffer]
    # these are small objects that describe atomic events,
    # like file move, registery access.
    # we'll detect the same with our API call analyis.
    enhanced: Skip = None


class Target(ExactModel):
    category: str
    file: File


class Static(ExactModel):
    pe: PE
    flare_capa: Skip = None


class CAPE(ExactModel):
    payloads: List[ProcessFile]
    configs: Skip = None


# flexible because there may be more sorts of analysis
# but we only care about the ones described here.
class CapeReport(FlexibleModel):
    # the input file, I think
    target: Target

    #
    # static analysis results
    #
    static: Optional[Static] = None
    strings: Optional[List[str]] = None

    #
    # dynamic analysis results
    #
    # post-processed results: process tree, anomalies, etc
    behavior: Behavior

    # post-processed results: payloads and extracted configs
    CAPE: CAPE
    dropped: Optional[List[File]] = None
    procdump: List[ProcessFile]
    procmemory: ListTODO

    # =========================================================================
    # information we won't use in capa
    #

    #
    # NBIs and HBIs
    # these are super interesting, but they don't enable use to detect behaviors.
    # they take a lot of code to model and details to maintain.
    #
    # if we come up with a future use for this, go ahead and re-enable!
    #
    network: Skip = None
    suricata: Skip = None
    curtain: Skip = None
    sysmon: Skip = None
    url_analysis: Skip = None

    # screenshot hash values
    deduplicated_shots: Skip = None
    # info about the processing job, like machine and distributed metadata.
    info: Skip = None
    # k-v pairs describing the time it took to run each stage.
    statistics: Skip = None
    # k-v pairs of ATT&CK ID to signature name or similar.
    ttps: Skip = None
    # debug log messages
    debug: Skip = None

    # various signature matches
    # we could potentially extend capa to use this info one day,
    # though it would be quite sandbox-specific,
    # and more detection-oriented than capability detection.
    signatures: Skip = None
    malfamily_tag: Optional[str] = None
    malscore: float
    detections: Skip = None
    detections2pid: Optional[Dict[int, List[str]]] = None
    # AV detections for the sample.
    virustotal: Skip = None

    @classmethod
    def from_buf(cls, buf: bytes) -> "CapeReport":
        return cls.model_validate_json(buf)
