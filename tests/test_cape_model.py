# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import gzip
from typing import Any, List, Dict, Optional, Union, Tuple
from typing_extensions import TypeAlias, Annotated

import pydantic
from pydantic import Field, BaseModel, ConfigDict
from pydantic.functional_validators import BeforeValidator


import fixtures


# mark fields that we haven't seen yet and need to model.
# pydantic should raise an error when encountering data
# in a field with this type.
# then we can update the model with the discovered shape.
TODO: TypeAlias = None
ListTODO: TypeAlias = List[None]


def validate_hex(value):
    return int(value, 16) if isinstance(value, str) else value


HexInt = Annotated[int, BeforeValidator(validate_hex)]



class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
    ep_bytes: Optional[str] = None
    entrypoint: Optional[int] = None
    timestamp: Optional[str] = None

    @pydantic.validator("virtual_address", pre=True, always=True)
    @classmethod
    def set_virtual_address(cls, value):
        return validate_hex(value)


class Config(Model):
    pass


class CAPE(Model):
    payloads: List[Payload]
    configs: List[Config]


class Machine(Model):
    id: int
    status: str
    name: str
    label: str
    manager: str
    started_on: str
    shutdown_on: str


class Distributed(Model):
    pass


class Options(Model):
    pass


class Sample(Model):
    pass


class Info(Model):
    category: str
    custom: str
    distributed: Distributed
    duration: int
    ended: str
    id: int
    machine: Machine
    options: Options
    package: str
    parent_id: Optional[int] = None
    parent_sample: Sample
    route: bool
    shrike_refer: Optional[str] = None
    shrike_sid: Optional[int] = None
    shrike_msg: Optional[str] = None
    shrike_url: Optional[str] = None
    source_url: Optional[str] = None
    started: str
    timeout: bool
    tlp: Optional[str] = None
    user_id: int
    version: str


class Argument(Model):
    name: str
    value: Union[int, str]
    pretty_value: Optional[str] = None

    @pydantic.validator("value", pre=True, always=True)
    @classmethod
    def set_value(cls, value):
        try:
            return validate_hex(value)
        except ValueError:
            return value


class Call(Model):
    timestamp: str
    thread_id: int
    caller: int
    parentcaller: int
    category: str
    api: str
    status: bool
    return_: int = Field(alias="return")
    pretty_return: Optional[str] = None
    arguments: List[Argument]
    repeated: int
    id: int

    @pydantic.validator("caller", pre=True, always=True)
    @classmethod
    def set_caller(cls, value):
        return validate_hex(value)

    @pydantic.validator("parentcaller", pre=True, always=True)
    @classmethod
    def set_parentcaller(cls, value):
        return validate_hex(value)


    @pydantic.validator("return_", pre=True, always=True)
    @classmethod
    def set_return_(cls, value):
        return validate_hex(value)


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
    moduleaddress: Optional[int] = None

    @pydantic.validator("moduleaddress", pre=True, always=True)
    @classmethod
    def set_moduleaddress(cls, value):
        return validate_hex(value)


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


class File(Model):
    name: Union[List[str], str]
    path: str
    guest_paths: Union[List[str], str, None]
    timestamp: Optional[str] = None
    size: int
    entrypoint: Optional[int] = None
    ep_bytes: Optional[str] = None  # TODO: hex-encoded string
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
    data: Optional[str] = None
 

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
    pcap_sha256: str
    hosts: List[Host]
    domains: List[Domain]
    tcp: List[TcpConnection]
    udp: List[UdpConnection]
    icmp: ListTODO
    http: ListTODO
    dns: List[DnsResolution]
    smtp: ListTODO
    irc: ListTODO
    dead_hosts: List[Tuple[str, int]]

class ImportedSymbol(Model):
    address: int
    name: str

    @pydantic.validator("address", pre=True, always=True)
    @classmethod
    def set_address(cls, value):
        return validate_hex(value)


class ImportedDll(Model):
    dll: str
    imports: List[ImportedSymbol]


class DirectoryEntry(Model):
    name: str
    virtual_address: int
    size: int

    @pydantic.validator("virtual_address", pre=True, always=True)
    @classmethod
    def set_virtual_address(cls, value):
        return validate_hex(value)

    @pydantic.validator("size", pre=True, always=True)
    @classmethod
    def set_size(cls, value):
        return validate_hex(value)


class Section(Model):
    name: str
    raw_address: int
    virtual_address: int
    virtual_size: int
    size_of_raw_data: Optional[int] = None
    size_of_data: int
    characteristics: str
    characteristics_raw: int
    entropy: float

    @pydantic.validator("raw_address", pre=True, always=True)
    @classmethod
    def set_raw_address(cls, value):
        return validate_hex(value)

    @pydantic.validator("virtual_address", pre=True, always=True)
    @classmethod
    def set_virtual_address(cls, value):
        return validate_hex(value)

    @pydantic.validator("virtual_size", pre=True, always=True)
    @classmethod
    def set_virtual_size(cls, value):
        return validate_hex(value)

    @pydantic.validator("size_of_raw_data", pre=True, always=True)
    @classmethod
    def set_size_of_raw_data(cls, value):
        return validate_hex(value)

    @pydantic.validator("size_of_data", pre=True, always=True)
    @classmethod
    def set_size_of_data(cls, value):
        return validate_hex(value)

    @pydantic.validator("characteristics_raw", pre=True, always=True)
    @classmethod
    def set_characteristics_raw(cls, value):
        return validate_hex(value)


class Signer(Model):
    aux_sha1: TODO
    aux_timestamp: None
    aux_valid: bool
    aux_error: bool
    aux_error_desc: str
    aux_signers: ListTODO


class PE(Model):
    peid_signatures: TODO
    imagebase: int
    entrypoint: int
    reported_checksum: int
    actual_checksum: int
    osversion: str
    pdbpath: Optional[str] = None
    timestamp: str

    imports: List[ImportedDll]
    imported_dll_count: int
    imphash: str

    exported_dll_name: Optional[str] = None
    exports: ListTODO

    dirents: List[DirectoryEntry]
    sections: List[Section]

    overlay: TODO
    resources: ListTODO
    icon: TODO
    icon_hash: TODO
    icon_fuzzy: TODO
    versioninfo: ListTODO

    digital_signers: ListTODO
    guest_signers: Signer

    @pydantic.validator("imagebase", pre=True, always=True)
    @classmethod
    def set_imagebase(cls, value):
        return validate_hex(value)

    @pydantic.validator("entrypoint", pre=True, always=True)
    @classmethod
    def set_entrypoint(cls, value):
        return validate_hex(value)

    @pydantic.validator("reported_checksum", pre=True, always=True)
    @classmethod
    def set_reported_checksum(cls, value):
        return validate_hex(value)

    @pydantic.validator("actual_checksum", pre=True, always=True)
    @classmethod
    def set_actual_checksum(cls, value):
        return validate_hex(value)


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


class Static(Model):
    pe: PE


class Suricata(Model):
    alerts: ListTODO
    dns: ListTODO
    fileinfo: ListTODO
    files: ListTODO
    http: ListTODO
    perf: ListTODO
    ssh: ListTODO
    tls: ListTODO
    alert_log_full_path: TODO
    dns_log_full_path: TODO
    eve_log_full_path: TODO
    file_log_full_path: TODO
    http_log_full_path: TODO
    ssh_log_full_path: TODO
    tls_log_full_path: TODO


class Target(Model):
    category: str
    file: File


class TTP(Model):
    ttp: str
    signature: str


class CapeReport(Model):
    statistics: Statistics
    detections: str
    detections2pid: Dict[int, List[str]]
    CAPE: CAPE
    info: Info
    behavior: Behavior
    curtain: TODO
    debug: Debug
    deduplicated_shots: List[int]
    dropped: List[File]
    network: Network
    procdump: List[Payload]
    static: Static
    strings: List[str]
    suricata: Suricata
    target: Target
    procmemory: ListTODO
    malfamily_tag: str
    signatures: List[Signature]
    malscore: float
    ttps: List[TTP]

    @classmethod
    def from_buf(cls, buf: bytes) -> "CapeReport":
        return cls.model_validate_json(buf)


def test_foo():
    path = fixtures.get_data_path_by_name("0000a657")
    buf = gzip.decompress(path.read_bytes())

    import json
    doc = json.loads(buf.decode("utf-8"))

    from pprint import pprint
    from rich import inspect

    #inspect(doc)
    #pprint(doc)
    print(doc.keys())

    print(doc["ttps"][0].keys())
    pprint(doc["ttps"])
    #from IPython import embed; embed()

    # K = "behavior"
    # inspect(doc[K])
    # pprint(doc[K])

    report = CapeReport.from_buf(buf)
    assert False, "end of foo"
    return



    assert report is not None


if __name__ == "__main__":
    test_foo()