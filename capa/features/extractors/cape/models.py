# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import binascii
from typing import Any, Dict, List, Tuple, Union, Literal, Optional

from pydantic import Field, BaseModel, ConfigDict
from typing_extensions import Annotated, TypeAlias
from pydantic.functional_validators import BeforeValidator


def validate_hex_int(value):
    return int(value, 16) if isinstance(value, str) else value


def validate_hex_bytes(value):
    return binascii.unhexlify(value) if isinstance(value, str) else value


HexInt = Annotated[int, BeforeValidator(validate_hex_int)]
HexBytes = Annotated[bytes, BeforeValidator(validate_hex_bytes)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
DictTODO: TypeAlias = Model

EmptyDict: TypeAlias = BaseModel
EmptyList: TypeAlias = List[Any]


class ImportedSymbol(Model):
    address: HexInt
    name: str


class ImportedDll(Model):
    dll: str
    imports: List[ImportedSymbol]


class DirectoryEntry(Model):
    name: str
    virtual_address: HexInt
    size: HexInt


class Section(Model):
    name: str
    raw_address: HexInt
    virtual_address: HexInt
    virtual_size: HexInt
    size_of_data: HexInt
    characteristics: str
    characteristics_raw: HexInt
    entropy: float


class Resource(Model):
    name: str
    language: Optional[str] = None
    sublanguage: str
    filetype: Optional[str]
    offset: HexInt
    size: HexInt
    entropy: float


class Signature(Model):
    alert: bool
    confidence: int
    data: List[Dict[str, Any]]
    description: str
    families: List[str]
    name: str
    new_data: ListTODO
    references: List[str]
    severity: int
    weight: int


class DigitalSigner(Model):
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


class Signer(Model):
    aux_sha1: Optional[TODO] = None
    aux_timestamp: Optional[None] = None
    aux_valid: Optional[bool] = None
    aux_error: Optional[bool] = None
    aux_error_desc: Optional[str] = None
    aux_signers: Optional[ListTODO] = None


class Overlay(Model):
    offset: HexInt
    size: HexInt


class KV(Model):
    name: str
    value: str


class ExportedSymbol(Model):
    address: HexInt
    name: str
    ordinal: int


class PE(Model):
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
    imported_dll_count: int
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


class File(Model):
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
    tlsh: str
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


class Argument(Model):
    name: str
    # unsure why empty list is provided here
    value: Union[HexInt, str, EmptyList]
    pretty_value: Optional[str] = None


class Call(Model):
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


class Process(Model):
    process_id: int
    process_name: str
    parent_id: int
    module_path: str
    first_seen: str
    calls: List[Call]
    threads: List[int]
    environ: Dict[str, str]


class ProcessTree(Model):
    name: str
    pid: int
    parent_id: int
    module_path: str
    threads: List[int]
    environ: Dict[str, str]
    children: List["ProcessTree"]


class EventFileData(Model):
    file: str
    pathtofile: Optional[str] = None
    moduleaddress: Optional[HexInt] = None


class EventRegData(Model):
    regkey: str
    content: Optional[str] = None


class EventMoveData(Model):
    from_: Optional[str] = Field(alias="from")
    to: Optional[str] = None


class EventSvcData(Model):
    service: str


class EnhancedEvent(Model):
    event: str
    object: str
    timestamp: str
    eid: int
    data: Union[EventFileData, EventRegData, EventMoveData, EventSvcData]


class Summary(Model):
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


class EncryptedBuffer(Model):
    process_name: str
    pid: int

    api_call: str
    buffer: str
    buffer_size: int


class Behavior(Model):
    summary: Summary

    # list of processes, of threads, of calls
    processes: List[Process]
    # tree of processes
    processtree: List[ProcessTree]

    anomaly: List[str]
    enhanced: List[EnhancedEvent]
    encryptedbuffers: List[EncryptedBuffer]


class Host(Model):
    ip: str
    country_name: str
    hostname: str
    inaddrarpa: str


class Domain(Model):
    domain: str
    ip: str


class TcpEvent(Model):
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float


class UdpEvent(Model):
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float


class DnsEventAnswer(Model):
    type: str
    data: str


class DnsEvent(Model):
    request: str
    type: str
    answers: List[DnsEventAnswer]


class IcmpEvent(Model):
    src: str
    dst: str
    type: int
    data: str


class Network(Model):
    pcap_sha256: Optional[str] = None
    hosts: Optional[List[Host]] = None
    domains: Optional[List[Domain]] = None
    tcp: Optional[List[TcpEvent]] = None
    udp: Optional[List[UdpEvent]] = None
    icmp: Optional[List[IcmpEvent]] = None
    http: Optional[ListTODO] = None
    dns: Optional[List[DnsEvent]] = None
    smtp: Optional[ListTODO] = None
    irc: Optional[ListTODO] = None
    domainlookups: Optional[DictTODO] = None
    iplookups: Optional[DictTODO] = None
    http_ex: Optional[ListTODO] = None
    https_ex: Optional[ListTODO] = None
    smtp_ex: Optional[ListTODO] = None
    dead_hosts: Optional[List[Tuple[str, int]]] = None


class DnsAnswer(Model):
    rdata: str
    rrname: str
    rrtype: str
    ttl: int


class SuricataDnsEvent(Model):
    id: int
    type: str
    rrname: str
    rrtype: str

    tx_id: Optional[int] = None

    # dict from query type ("A") to resolutions ("127.0.0.1")
    grouped: Optional[Dict[str, List[str]]] = None
    answers: Optional[List[DnsAnswer]] = None

    rcode: Optional[str] = None
    opcode: Optional[int] = None
    ra: Optional[bool] = None
    rd: Optional[bool] = None
    qr: Optional[bool] = None
    flags: Optional[int] = None
    version: Optional[int] = None


class SuricataNetworkEntry(Model):
    timestamp: str
    event_type: str
    proto: str

    flow_id: int
    pcap_cnt: int

    src_ip: str
    src_port: int

    dest_ip: str
    dest_port: int

    dns: Optional[SuricataDnsEvent]


class JA3(Model):
    hash: str
    string: str


class TLS(Model):
    timestamp: str

    srcip: str
    srcport: int

    dstip: str
    dstport: int

    version: str
    sni: str

    subject: Optional[str] = None
    issuerdn: Optional[str] = None
    notafter: Optional[str] = None
    notbefore: Optional[str] = None
    serial: Optional[str] = None
    fingerprint: Optional[str] = None

    ja3: Union[JA3, EmptyDict]
    ja3s: Union[JA3, EmptyDict]


class HTTP(Model):
    timestamp: str

    srcip: str
    srcport: int

    dstip: str
    dstport: int

    hostname: str
    http_method: str
    uri: str
    referrer: str
    ua: str

    status: int
    contenttype: str
    length: int


class Suricata(Model):
    alerts: ListTODO
    dns: List[SuricataNetworkEntry]
    fileinfo: ListTODO
    files: ListTODO
    http: List[HTTP]
    perf: ListTODO
    ssh: ListTODO
    tls: List[TLS]

    # paths to log files, not relevant to capa
    alert_log_full_path: Skip = None
    dns_log_full_path: Skip = None
    eve_log_full_path: Skip = None
    file_log_full_path: Skip = None
    http_log_full_path: Skip = None
    ssh_log_full_path: Skip = None
    tls_log_full_path: Skip = None


class Curtain(Model):
    # seems to be behavior analysis via event log monitoring?
    pid: int
    behaviors: List[str]
    filter: List[Any]
    events: List[Any]


class Target(Model):
    category: str
    file: File


class Static(Model):
    pe: PE
    flare_capa: Skip = None


class CAPE(Model):
    payloads: List[ProcessFile]
    configs: ListTODO


class CapeReport(Model):
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

    network: Network
    suricata: Suricata
    dropped: List[File]
    procdump: List[ProcessFile]
    procmemory: ListTODO

    #
    # unknown shapes
    #
    # seems to have to do with processing powershell logs.
    # disabled by default, and i don't see the source on github.
    curtain: Optional[Dict[int, Curtain]] = None
    sysmon: Optional[ListTODO] = None
    url_analysis: Optional[DictTODO] = None

    #
    # information we won't use in capa
    #

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
    signatures: List[Signature]
    malfamily_tag: Optional[str] = None
    malscore: float
    detections: Optional[str] = None
    detections2pid: Optional[Dict[int, List[str]]] = None
    # AV detections for the sample.
    virustotal: Skip = None

    @classmethod
    def from_buf(cls, buf: bytes) -> "CapeReport":
        return cls.model_validate_json(buf)


if __name__ == "__main__":
    import sys
    import gzip
    from pathlib import Path

    path = Path(sys.argv[1])
    buf = gzip.decompress(path.read_bytes())

    import json

    doc = json.loads(buf)

    from pprint import pprint

    # pprint(doc["behavior"]["encryptedbuffers"][0])
    # from IPython import embed; embed()

    report = CapeReport.from_buf(buf)
    assert report is not None
