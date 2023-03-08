import sys
import json

import capa.features.freeze
import capa.render.proto.capa_pb2
import capa.render.result_document
from capa.features.freeze import AddressType


def main():
    # first compile protobuf
    # protoc.exe --python_out . capa/render/proto/capa.proto

    fpath = sys.argv[1]
    with open(fpath, "r", encoding="utf-8") as f:
        fdata = f.read()

    doc = capa.render.result_document.ResultDocument.parse_obj(json.loads(fdata))

    p = to_proto(doc)

    print(p)


def to_proto(doc):
    m = metadata_from_capa(doc.meta)
    return m


def metadata_from_capa(meta: capa.render.result_document.Metadata) -> capa.render.proto.capa_pb2.Metadata:
    m = capa.render.proto.capa_pb2.Metadata()

    m.timestamp = str(meta.timestamp)  # TODO google.protobuf.timestamp_pb2.Timestamp?
    m.version = meta.version
    m.argv.extend(meta.argv)

    m.sample.md5 = meta.sample.md5
    m.sample.sha1 = meta.sample.sha1
    m.sample.sha256 = meta.sample.sha256
    m.sample.path = meta.sample.path

    m.analysis.format = meta.analysis.format
    m.analysis.arch = meta.analysis.arch
    m.analysis.os = meta.analysis.os
    m.analysis.extractor = meta.analysis.extractor
    m.analysis.rules.extend(meta.analysis.rules)
    m.analysis.base_address.CopyFrom(addr_from_freeze(meta.analysis.base_address))

    m.analysis.layout.CopyFrom(
        capa.render.proto.capa_pb2.Layout(
            functions=[
                capa.render.proto.capa_pb2.FunctionLayout(
                    address=addr_from_freeze(func.address),
                    matched_basic_blocks=[
                        capa.render.proto.capa_pb2.BasicBlockLayout(address=addr_from_freeze(bb.address))
                        for bb in func.matched_basic_blocks
                    ],
                )
                for func in meta.analysis.layout.functions
            ]
        )
    )

    m.analysis.feature_counts.file = meta.analysis.feature_counts.file
    m.analysis.feature_counts.functions.extend(
        [
            capa.render.proto.capa_pb2.FunctionFeatureCount(address=addr_from_freeze(ffc.address), count=ffc.count)
            for ffc in meta.analysis.feature_counts.functions
        ]
    )
    m.analysis.library_functions.extend(
        [
            capa.render.proto.capa_pb2.LibraryFunction(address=addr_from_freeze(lf.address), name=lf.name)
            for lf in meta.analysis.library_functions
        ]
    )

    return m


def addr_from_freeze(a: capa.features.freeze.Address) -> capa.render.proto.capa_pb2.Address:
    address = capa.render.proto.capa_pb2.Address()
    if a.type is AddressType.ABSOLUTE:
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_ABSOLUTE
        address.v.CopyFrom(int_to_pb2(a.value))
        return address

    elif a.type is AddressType.RELATIVE:
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_RELATIVE
        address.v.CopyFrom(int_to_pb2(a.value))
        return address

    elif a.type is AddressType.FILE:
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_FILE
        address.v.CopyFrom(int_to_pb2(a.value))
        return address

    elif a.type is AddressType.DN_TOKEN:
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN
        address.v.CopyFrom(int_to_pb2(a.value))
        return address

    elif a.type is AddressType.DN_TOKEN_OFFSET:
        token, offset = a.value
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN_OFFSET
        address.token_offset.token.CopyFrom(int_to_pb2(token))
        address.token_offset.offset = offset
        return address

    elif a.type is AddressType.NO_ADDRESS:
        address.type = capa.render.proto.capa_pb2.AddressType.ADDRESSTYPE_NO_ADDRESS
        # value == None so just don't set here
        return address

    else:
        raise NotImplementedError(f"unhandled address type {a.type} ({type(a.type).__name__})")


def int_to_pb2(v):
    assert isinstance(v, int)
    if v < -2_147_483_648:
        raise ValueError("underflow")
    if v > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("overflow")

    if v < 0:
        return capa.render.proto.capa_pb2.Integer(i=v)
    else:
        return capa.render.proto.capa_pb2.Integer(u=v)


if __name__ == "__main__":
    main()
