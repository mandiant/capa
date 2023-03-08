# Copyright (C) 2023 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import json
import pathlib
import subprocess

import pydantic
import capa.render
import capa.render.proto
import capa.render.utils
import capa.features.freeze
import capa.features.address
import capa.render.proto.proto
import capa.render.proto.capa_pb2
import capa.render.result_document
import capa.features.freeze.features
from fixtures import *
from capa.render.result_document import ResultDocument


# TODO enable/remove
def _test_generate_proto(tmp_path: pathlib.Path):
    tmp_path.mkdir(exist_ok=True, parents=True)
    proto_path = tmp_path / "capa.proto"
    json_path = tmp_path / "capa.json"

    schema = pydantic.schema_of(capa.render.result_document.ResultDocument)
    json_path.write_text(json.dumps(schema, indent=4))

    proto = capa.render.proto.generate_proto()

    print("=====================================")
    print(proto_path)
    print("-------------------------------------")
    for i, line in enumerate(proto.split("\n")):
        print(f" {i} | {line}")
    print("=====================================")
    proto_path.write_text(proto)

    subprocess.run(
        [
            "protoc",
            "-I=" + str(tmp_path),
            "--python_out=" + str(tmp_path),
            "--mypy_out=" + str(tmp_path),
            str(proto_path),
        ],
        check=True,
    )

    pb = tmp_path / "capa_pb2.py"
    print(pb.read_text())
    print("=====================================")


def test_translate_to_proto(pma0101_rd: ResultDocument):
    src = pma0101_rd

    meta = src.meta
    dst = capa.render.proto.proto.metadata_from_capa(meta)

    assert str(meta.timestamp) == dst.timestamp  # TODO type?
    assert meta.version == dst.version
    assert list(meta.argv) == dst.argv

    assert meta.sample.md5 == dst.sample.md5
    assert meta.sample.sha1 == dst.sample.sha1
    assert meta.sample.sha256 == dst.sample.sha256
    assert meta.sample.path == dst.sample.path

    assert meta.analysis.format == dst.analysis.format
    assert meta.analysis.arch == dst.analysis.arch
    assert meta.analysis.os == dst.analysis.os
    assert meta.analysis.extractor == dst.analysis.extractor
    assert list(meta.analysis.rules) == dst.analysis.rules
    assert capa.render.proto.proto.addr_from_freeze(meta.analysis.base_address) == dst.analysis.base_address

    assert len(meta.analysis.layout.functions) == len(dst.analysis.layout.functions)
    # TODO use zip()
    for i, f in enumerate(meta.analysis.layout.functions):
        assert capa.render.proto.proto.addr_from_freeze(f.address) == dst.analysis.layout.functions[i].address

        assert len(f.matched_basic_blocks) == len(dst.analysis.layout.functions[i].matched_basic_blocks)
        for j, bb in enumerate(f.matched_basic_blocks):
            assert (
                capa.render.proto.proto.addr_from_freeze(bb.address)
                == dst.analysis.layout.functions[i].matched_basic_blocks[j].address
            )

    assert meta.analysis.feature_counts.file == dst.analysis.feature_counts.file
    assert len(meta.analysis.feature_counts.functions) == len(dst.analysis.feature_counts.functions)
    for rd_f, proto_f in zip(meta.analysis.feature_counts.functions, dst.analysis.feature_counts.functions):
        assert capa.render.proto.proto.addr_from_freeze(rd_f.address) == proto_f.address
        assert rd_f.count == proto_f.count

    assert len(meta.analysis.library_functions) == len(dst.analysis.library_functions)
    for rd_lf, proto_lf in zip(meta.analysis.library_functions, dst.analysis.library_functions):
        assert capa.render.proto.proto.addr_from_freeze(rd_lf.address) == proto_lf.address
        assert rd_lf.name == proto_lf.name


def test_addr_from_freeze():
    a = capa.features.address.AbsoluteVirtualAddress(0x400000)
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_ABSOLUTE
    assert a.v0.u == 0x400000

    a = capa.features.address.RelativeVirtualAddress(0x100)
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_RELATIVE
    assert a.v0.u == 0x100

    a = capa.features.address.FileOffsetAddress(0x200)
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_FILE
    assert a.v0.u == 0x200

    a = capa.features.address.DNTokenAddress(0x123456)
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_DN_TOKEN
    assert a.v0.u == 0x123456

    a = capa.features.address.DNTokenOffsetAddress(0x123456, 0x10)
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_DN_TOKEN_OFFSET
    assert a.v1.v0.u == 0x123456
    assert a.v1.v1.u == 0x10

    a = capa.features.address._NoAddress()
    a = capa.features.freeze.Address.from_capa(a)
    a = capa.render.proto.proto.addr_from_freeze(a)
    assert a.type == capa.render.proto.capa_pb2.ADDRESSTYPE_NO_ADDRESS


# TODO proto to RD?
