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

from fixtures import *

import capa.render
import capa.render.proto
import capa.render.utils
import capa.features.freeze
import capa.render.proto.capa_pb2
import capa.render.result_document
import capa.features.freeze.features
from capa.render.result_document import ResultDocument


def test_generate_proto(tmp_path: pathlib.Path):
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


def test_translate_to_pb2(pma0101_rd: ResultDocument):
    schema = pydantic.schema_of(capa.render.result_document.ResultDocument)
    src = pma0101_rd
    dst = capa.render.proto.capa_pb2.ResultDocument()
    typ = schema["definitions"]["ResultDocument"]

    capa.render.proto.translate_to_pb2(schema, typ, src, dst)
    
    print()
    print("=====================================")
    print(dst)
    print("=====================================")

    assert False
