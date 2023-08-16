# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import binascii
from typing import Any, Dict, List, Tuple, Union, Optional

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


# mark fields that we haven't seen yet and need to model.
# pydantic should raise an error when encountering data
# in a field with this type.
# then we can update the model with the discovered shape.
TODO: TypeAlias = None
ListTODO: TypeAlias = List[None]


class DictTODO(Model):
    pass


class Statistic(Model):
    name: str
    time: float


class Statistics(Model):
    processing: List[Statistic]
    signatures: List[Statistic]
    reporting: List[Statistic]


class Yara(Model):
    name: str
    strings: List[str]
    addresses: Dict[str, int]
    meta: Dict[str, str]


class ClamAV(Model):
    name: str


class Payload(Model):
    cape_type_code: Optional[int] = None
    cape_type: str
    name: str
    path: str
    guest_paths: str
    size: int
    crc32: str
    md5: str
    sha1: str
    sha256: str
    sha512: str
    sha3_384: str
    ssdeep: str
    type: str
    yara: List[Yara]
    cape_yara: List[Yara]
    clamav: List[ClamAV]
    tlsh: str
    pid: int
    process_path: str
    process_name: str
    module_path: str
    virtual_address: Optional[HexInt] = None
    target_pid: Optional[int] = None
    target_path: Optional[str] = None
    target_process: Optional[str] = None
    ep_bytes: Optional[HexBytes] = None
    entrypoint: Optional[int] = None
    timestamp: Optional[str] = None


class CAPE(Model):
    payloads: List[Payload]
    configs: ListTODO


class Machine(Model):
    id: int
    status: str
    name: str
    label: str
    manager: str
    started_on: str
    shutdown_on: str


class Info(Model):
    category: str
    custom: str
    distributed: Optional[DictTODO] = None
    duration: int
    ended: str
    id: int
    machine: Machine
    options: DictTODO
    package: str
    parent_id: Optional[int] = None
    parent_sample: DictTODO
    route: Optional[bool] = None
    shrike_refer: Optional[str] = None
    shrike_sid: Optional[int] = None
    shrike_msg: Optional[str] = None
    shrike_url: Optional[str] = None
    source_url: Optional[str] = None
    started: str
    timeout: bool
    tlp: Optional[str] = None
    user_id: Optional[int] = None
    version: str


class Argument(Model):
    name: str
    value: Union[HexInt, str]
    pretty_value: Optional[str] = None


class Call(Model):
    timestamp: str
    thread_id: int
    caller: HexInt
    parentcaller: HexInt
    category: str
    api: str
    status: bool
    return_: HexInt = Field(alias="return")
    pretty_return: Optional[str] = None
    arguments: List[Argument]
    repeated: int
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


class EnhancedEvent(Model):
    event: str
    object: str
    timestamp: str
    eid: int
    data: Union[EventFileData, EventRegData, EventMoveData]


class Behavior(Model):
    processes: List[Process]
    anomaly: List[str]
    processtree: List[ProcessTree]
    summary: Summary
    enhanced: List[EnhancedEvent]
    encryptedbuffers: ListTODO


class Debug(Model):
    log: str
    errors: List[str]


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


class Signer(Model):
    aux_sha1: Optional[TODO] = None
    aux_timestamp: Optional[None] = None
    aux_valid: Optional[bool] = None
    aux_error: Optional[bool] = None
    aux_error_desc: Optional[str] = None
    aux_signers: Optional[ListTODO] = None


class Resource(Model):
    name: str
    language: str
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


class Overlay(Model):
    offset: HexInt
    size: HexInt


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
    exports: ListTODO

    dirents: List[DirectoryEntry]
    sections: List[Section]

    ep_bytes: Optional[HexBytes] = None

    overlay: Optional[Overlay] = None
    resources: List[Resource]
    icon: TODO
    icon_hash: TODO
    icon_fuzzy: TODO
    icon_dhash: Optional[TODO] = None
    versioninfo: ListTODO

    digital_signers: ListTODO
    guest_signers: Signer


class VirusTotalResult(Model):
    vendor: str
    sig: Optional[str]


class VirusTotalScan(Model):
    result: str
    detected: Optional[bool] = None
    update: Optional[str] = None
    version: Optional[str] = None
    engine_name: Optional[str] = None
    engine_version: Optional[str] = None
    engine_update: Optional[str] = None
    method: Optional[str] = None
    category: Optional[str] = None


class VirusTotal(Model):
    md5: str
    sha1: str
    sha256: str
    tlsh: Optional[str] = None
    permalink: str
    positives: Optional[int] = None
    positive: Optional[int] = None
    detection: Optional[str] = None
    total: int
    resource: str
    response_code: Optional[int] = None
    names: Optional[List[str]] = None
    results: List[VirusTotalResult]
    scan_date: Optional[str] = None
    scan_id: str
    scans: Dict[str, VirusTotalScan]
    verbose_msg: Optional[str] = None


class VirusTotalError(Model):
    error: bool
    msg: str


class File(Model):
    type: str
    name: Union[List[str], str]
    path: str
    guest_paths: Union[List[str], str, None]
    timestamp: Optional[str] = None
    size: int
    entrypoint: Optional[int] = None
    ep_bytes: Optional[HexBytes] = None
    crc32: str
    md5: str
    sha1: str
    sha256: str
    sha512: str
    sha3_384: str
    rh_hash: Optional[str] = None
    ssdeep: str
    tlsh: str
    yara: List[Yara]
    cape_yara: List[Yara]
    clamav: List[ClamAV]
    data: Optional[str] = None
    pe: Optional[PE] = None
    strings: Optional[List[str]] = None
    virustotal: Optional[Union[VirusTotal, VirusTotalError]] = None


class Host(Model):
    ip: str
    country_name: str
    hostname: str
    inaddrarpa: str


class Domain(Model):
    domain: str
    ip: str


class TcpConnection(Model):
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float


class UdpConnection(Model):
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float


class DnsResolution(Model):
    request: str
    type: str
    answers: ListTODO


class Network(Model):
    pcap_sha256: Optional[str] = None
    hosts: Optional[List[Host]] = None
    domains: Optional[List[Domain]] = None
    tcp: Optional[List[TcpConnection]] = None
    udp: Optional[List[UdpConnection]] = None
    icmp: Optional[ListTODO] = None
    http: Optional[ListTODO] = None
    dns: Optional[List[DnsResolution]] = None
    smtp: Optional[ListTODO] = None
    irc: Optional[ListTODO] = None
    domainlookups: Optional[DictTODO] = None
    iplookups: Optional[DictTODO] = None
    http_ex: Optional[ListTODO] = None
    https_ex: Optional[ListTODO] = None
    smtp_ex: Optional[ListTODO] = None
    dead_hosts: Optional[List[Tuple[str, int]]] = None


class FlareCapa(Model):
    ATTCK: Dict[str, List[str]]
    CAPABILITY: Dict[str, List[str]]
    MBC: Dict[str, List[str]]
    md5: str
    sha1: str
    sha256: str
    path: str


class Static(Model):
    pe: PE
    flare_capa: Optional[FlareCapa] = None


class DnsEvent(Model):
    id: int
    type: str
    rrname: str
    rrtype: str
    tx_id: int


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

    dns: Optional[DnsEvent]


class Suricata(Model):
    alerts: ListTODO
    dns: List[SuricataNetworkEntry]
    fileinfo: ListTODO
    files: ListTODO
    http: ListTODO
    perf: ListTODO
    ssh: ListTODO
    tls: ListTODO
    alert_log_full_path: Optional[str] = None
    dns_log_full_path: Optional[str] = None
    eve_log_full_path: Optional[str] = None
    file_log_full_path: Optional[str] = None
    http_log_full_path: Optional[str] = None
    ssh_log_full_path: Optional[str] = None
    tls_log_full_path: Optional[str] = None


class Target(Model):
    category: str
    file: File


class TTP(Model):
    ttp: str
    signature: str


class CapeReport(Model):
    behavior: Behavior
    CAPE: CAPE
    curtain: Optional[TODO] = None
    debug: Debug
    deduplicated_shots: Optional[List[int]] = None
    detections: Optional[str] = None
    detections2pid: Optional[Dict[int, List[str]]] = None
    dropped: List[File]
    info: Info
    malfamily_tag: Optional[str] = None
    malscore: float
    network: Network
    procdump: List[Payload]
    procmemory: ListTODO
    signatures: List[Signature]
    static: Optional[Static] = None
    statistics: Optional[Statistics] = None
    strings: Optional[List[str]] = None
    suricata: Suricata
    sysmon: Optional[ListTODO] = None
    target: Target
    # List[TTP{ttp, signature}] or Dict[ttp, signature]
    ttps: Union[List[TTP], Dict[str, str]]
    virustotal: Optional[VirusTotal] = None

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

    #pprint(doc["target"]["file"]["pe"]["imports"])

    report = CapeReport.from_buf(buf)
    assert report is not None
