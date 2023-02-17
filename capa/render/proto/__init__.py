# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import logging
from typing import Dict, Union
from dataclasses import dataclass

import pydantic

import capa.render
import capa.render.utils
import capa.features.freeze
import capa.render.result_document
import capa.features.freeze.features
from capa.render.utils import StringIO


logger = logging.getLogger(__name__)


def is_enum(prop):
    return "type" in prop and prop["type"] == "string" and "enum" in prop


def get_enum_name(prop):
    return prop["title"]


def get_enum_value_name(enum, value):
    # like: ADDRESSTYPE
    prefix = get_enum_name(enum).upper()

    # like: ADDRESSTYPE_ABSOLUTE
    return "%s_%s" % (prefix, value.upper().replace(" ", "_"))


def emit_proto_enum(out: StringIO, enum):
    # like:
    #
    #     enum AddressType {
    #         ADDRESSTYPE_UNSPECIFIED = 0;
    #         ADDRESSTYPE_ABSOLUTE = 1;
    #         ADDRESSTYPE_RELATIVE = 2;
    #         ...
    #     }
    out.writeln(f"enum {get_enum_name(enum)} {{")
    out.writeln(f'  {get_enum_value_name(enum, "unspecified")} = 0;')
    for i, value in enumerate(enum["enum"]):
        out.writeln(f"  {get_enum_value_name(enum, value)} = {i + 1};")
    out.writeln(f"}}")
    out.writeln("")


def is_ref(prop):
    return "$ref" in prop


def get_ref_type_name(prop):
    # from: {"$ref": "#/definitions/Scope"}},
    # to: "Scope"

    assert is_ref(prop)
    assert prop["$ref"].startswith("#/definitions/")

    return prop["$ref"][len("#/definitions/") :]


def is_primitive_type(prop):
    # things like: string, integer, bool, etc.
    return "type" in prop and not prop["type"] == "object" and not "enum" in prop


def is_custom_type(prop):
    # struct-like things defined in the schema, like Features, etc.
    return "type" in prop and prop["type"] == "object" and "additionalProperties" not in prop


def get_custom_type_name(prop):
    return prop["title"]


def is_tuple(prop):
    # a tuple is an array with a fixed size.
    # the types of the elements can vary.
    # we'll emit a custom message type for each tuple, like Pair_Address_Match.
    #
    # like:
    #
    #     {"items": [{"$ref": "#/definitions/Address"},
    #                {"$ref": "#/definitions/Match"}],
    #      "maxItems": 2,
    #      "minItems": 2,
    #      "type": "array"},

    if "type" not in prop:
        return False

    if prop["type"] != "array":
        return False

    if "maxItems" not in prop or "minItems" not in prop:
        return False
    if prop["maxItems"] != prop["minItems"]:
        # tuples have a fixed size
        return False

    return True


def get_tuple_type_name(prop):
    assert is_tuple(prop)

    if prop["maxItems"] == 2:
        base = "Pair"
    else:
        base = "Tuple"

    # this won't work for nested tuples, but good enough for here.
    return base + "_" + "_".join(get_type_name(item) for item in prop["items"])


def is_array(prop):
    # an array is a sequence of elements of the same type.
    # typically we can use a repeated field for this.
    # note: there's a special case within maps, where the array elements are a custom wrapper type.
    #
    # like:
    #
    #    {"items": {"type": "string"},
    #     "title": "Parts",
    #     "type": "array"},

    if "type" not in prop:
        return False

    if prop["type"] != "array":
        return False

    if "maxItems" in prop and "minItems" in prop and prop["maxItems"] == prop["minItems"]:
        # tuples have a fixed size, arrays are variable
        return False

    if not isinstance(prop["items"], dict):
        # array elements have a fixed type
        return False

    return True


def is_map(prop):
    # a map maps from string key to a fixed type.
    # the value type cannot be repeated, so we'll emit a custom wrapper type.
    #
    # like:
    #
    #    {"additionalProperties": {"items": {"$ref": "#/definitions/Address"},
    #                              "type": "array"},
    #     "title": "Captures",
    #     "type": "object"},
    return "type" in prop and prop["type"] == "object" and "additionalProperties" in prop


def get_primitive_type_name(prop):
    assert is_primitive_type(prop)

    if prop["type"] == "string":
        return "string"

    elif prop["type"] == "boolean":
        return "bool"

    elif prop["type"] == "integer":
        # this integer has arbitrary range.
        # but proto supports only i64 and u64.
        # so we hook this specially, including within the translator.
        return "Integer"

    elif prop["type"] == "number":
        # number: int | float
        # we hook this specially
        return "Number"

    elif is_tuple(prop):
        return get_tuple_type_name(prop)

    elif is_array(prop):
        aitem = prop["items"]

        if is_primitive_type(aitem):
            atype = get_primitive_type_name(prop["items"])

        elif is_ref(aitem):
            atype = get_ref_type_name(aitem)

        elif is_custom_type(aitem):
            atype = get_custom_type_name(aitem)

        else:
            raise NotImplementedError(aitem)

        return f"repeated {atype}"

    else:
        raise NotImplementedError(prop["type"])


def get_type_name(prop):
    if is_primitive_type(prop):
        return get_primitive_type_name(prop)
    elif is_custom_type(prop):
        return get_custom_type_name(prop)
    elif is_ref(prop):
        return get_ref_type_name(prop)
    elif is_enum(prop):
        return get_enum_name(prop)
    else:
        raise NotImplementedError(prop)


def is_union(prop):
    # a union is a field that can be one of several types.
    return "anyOf" in prop


def sanitize_prop_name(name):
    # like: "analysis-conclusion" -> "analysis_conclusion"
    # like: "att&ck" -> "attack"
    # like: "capa/subscope" -> "capa-subscope"
    # like: "function name" -> "function-name"
    return name.replace("-", "_").replace("&", "a").replace("/", "_").replace(" ", "_")


def _find_capa_class(name):
    # try to find the capa class that corresponds to the given name.
    # we use this to find the class that defines the property order.

    try:
        return getattr(capa.render.result_document, name)
    except AttributeError:
        pass

    try:
        return getattr(capa.features.freeze, name)
    except AttributeError:
        pass

    try:
        return getattr(capa.features.freeze.features, name)
    except AttributeError:
        pass

    raise NotImplementedError(name)


def _enum_properties(message):
    """enumerate the properties of the message defined, ordered by class declaration"""
    # this is just for convenience.

    # the order of properties provided by the class. guaranteed.
    property_order = list(_find_capa_class(message["title"]).__signature__.parameters.keys())
    # order of properties provided by pydantic. not guaranteed. the fallback.
    # used when we can't figure out an alias, such as capa/subscope -> is_subscope.
    properties = list(message["properties"].keys())

    def get_property_index(name):
        try:
            # prefer the order of properties provided by the class.
            return property_order.index(sanitize_prop_name(name))
        except ValueError:
            # fallback to whatever pydantic extracts.
            return len(message["properties"]) + properties.index(name)

    return sorted(message["properties"].items(), key=lambda p: get_property_index(p[0]))


@dataclass
class DeferredArrayType:
    name: str
    item: dict


@dataclass
class DeferredTupleType:
    name: str
    count: int
    items: dict


def emit_proto_message(out: StringIO, deferred_types: Dict, message):
    # like: Address
    title = message["title"]

    out.writeln(f"message {title} {{")
    counter = iter(range(1, sys.maxsize))
    for raw_name, prop in _enum_properties(message):
        # we use a counter like this so that
        # union/oneof fields can increment the counter.
        i = next(counter)
        name = sanitize_prop_name(raw_name)

        if is_ref(prop):
            ptype = get_ref_type_name(prop)
            out.writeln(f"  {ptype} {name} = {i};")

        elif is_primitive_type(prop):
            ptype = get_primitive_type_name(prop)
            out.writeln(f"  {ptype} {name} = {i};")

            if is_tuple(prop):
                deferred_types[ptype] = DeferredTupleType(ptype, prop["minItems"], prop["items"])

            elif is_array(prop):
                aitem = prop["items"]

                if is_tuple(aitem):
                    atype = get_tuple_type_name(aitem)
                    deferred_types[atype] = DeferredTupleType(atype, aitem["minItems"], aitem["items"])

        elif is_custom_type(prop):
            ptype = get_custom_type_name(prop)
            out.writeln(f"  {ptype} {name} = {i};")

        elif is_union(prop):
            out.writeln(f"  oneof {name} {{")

            for j, of in enumerate(prop["anyOf"]):
                if is_ref(of):
                    ptype = get_ref_type_name(of)
                    out.writeln(f"    {ptype} v{j} = {i};")

                elif is_primitive_type(of):
                    ptype = get_primitive_type_name(of)
                    out.writeln(f"    {ptype} v{j} = {i};")

                    if is_tuple(of):
                        deferred_types[ptype] = DeferredTupleType(ptype, of["minItems"], of["items"])

                # pydantic doesn't seem to encode None option
                # fortunately, neither does protobuf.
                # still seems weird not to be explicit.

                else:
                    raise NotImplementedError(of)

                i = next(counter)

            out.writeln(f"  }};")

        elif is_map(prop):
            if is_array(prop["additionalProperties"]):
                # map values cannot be repeated, see:
                # https://stackoverflow.com/a/41552990/87207
                #
                # so create a wrapper type around the repeated values.
                # like: message Array_Integer { repeated int32 values = 1; }
                #
                # no:
                #
                #     map <string, repeated int32> things = 1;
                #
                # yes:
                #
                #     map <string, Array_Integer> things = 1;
                #
                # we could do this for every array, like Array_Integer and Array_Address,
                # but its less idiomatic and more noisy.
                # so we only create these types when we need them.
                item_def = prop["additionalProperties"]["items"]

                vtype = "Array_" + get_type_name(item_def)

                # register this type to be emitted once we're done with the
                # top level custom types in the schema.
                deferred_types[vtype] = DeferredArrayType(vtype, item_def)

            else:
                vtype = get_type_name(prop["additionalProperties"])

            out.writeln(f"  map <string, {vtype}> {name} = {i};")

        else:
            raise ValueError("unexpected type: %s" % prop)

    out.writeln(f"}}")
    out.writeln("")


def emit_proto_entry(out: StringIO, deferred_types: Dict, schema, name):
    if not name.startswith("#/definitions/"):
        raise ValueError("unexpected name: %s" % name)

    title = name[len("#/definitions/") :]
    definition = schema["definitions"][title]

    if definition["title"] != title:
        raise ValueError("title mismatch: %s" % definition["title"])

    if definition["type"] == "string" and "enum" in definition:
        emit_proto_enum(out, definition)

    elif definition["type"] == "object":
        emit_proto_message(out, deferred_types, definition)

    else:
        raise NotImplementedError(definition["type"])


def generate_proto_from_pydantic(schema):
    out: StringIO = capa.render.utils.StringIO()
    out.writeln("// Generated by the capa.render.proto translator. DO NOT EDIT!")
    out.writeln('syntax = "proto3";')
    out.writeln("")

    deferred_types: Dict[str, Union[DeferredArrayType, DeferredTupleType]] = dict()
    for name in sorted(schema["definitions"].keys()):
        emit_proto_entry(out, deferred_types, schema, "#/definitions/" + name)

    for name, deferred_type in sorted(deferred_types.items()):
        if isinstance(deferred_type, DeferredArrayType):
            vtype = get_type_name(deferred_type.item)
            out.writeln(f"message {name} {{ repeated {vtype} values = 1; }}\n")
        elif isinstance(deferred_type, DeferredTupleType):
            out.writeln(f"message {name} {{")
            for i, item in enumerate(deferred_type.items):
                vtype = get_type_name(item)
                out.writeln(f"  {vtype} v{i} = {i + 1};")
            out.writeln(f"}}\n")

    # these are additional primitive types that we'll use throughout.
    out.writeln("message Integer { oneof value { uint64 u = 1; int64 i = 2; } }\n")
    out.writeln("message Number { oneof value { uint64 u = 1; int64 i = 2; double f = 3; } }\n")

    return out.getvalue()


def generate_proto() -> str:
    """
    generate a protobuf v3 schema for the ResultDocument format.
    we use introspection of the pydantic schema to generate this.

    note: we *cannot* use the generated proto from version to version of capa,
    because this translator does guarantee field ordering/numbering.
    that is, if we add a new property to any of the pydantic models,
    the proto field numbers may change, and any clients using the proto will break.

    instead, we should use this method to generate the proto,
    probably once per major version,
    and then commit the proto to the repo.
    """
    return generate_proto_from_pydantic(pydantic.schema_of(capa.render.result_document.ResultDocument))


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
 

def translate_to_pb2(schema, typ, src, dst):
    logger.debug("translate: %s", get_type_name(typ))
    if is_custom_type(typ):
        for pname, ptyp in typ["properties"].items():
            if is_union(ptyp):
                logger.debug("translate: %s.%s (union)", get_type_name(typ), pname)
            elif is_map(ptyp):
                logger.debug("translate: %s.%s (map)", get_type_name(typ), pname)
            else:
                logger.debug("translate: %s.%s (%s)", get_type_name(typ), pname, get_type_name(ptyp))

            psrc = getattr(src, pname)

            if is_ref(ptyp):
                logger.debug("resolving ref: %s", get_type_name(ptyp))
                ptyp = schema["definitions"][get_ref_type_name(ptyp)]

            if is_primitive_type(ptyp):
                if ptyp["type"] == "string":
                    if "format" in ptyp and ptyp["format"] == "date-time":
                        pdst = psrc.isoformat("T") + "Z"
                    else:
                        pdst = psrc

                    setattr(dst, pname, pdst)

                elif ptyp["type"] == "integer":
                    getattr(dst, pname).CopyFrom(int_to_pb2(psrc))

                # TODO: move array out of primitives
                elif is_array(ptyp):
                    vtyp = ptyp["items"]
                    if is_ref(vtyp):
                        logger.debug("resolving ref: %s", get_type_name(vtyp))
                        vtyp = schema["definitions"][get_ref_type_name(vtyp)]

                    if get_type_name(vtyp) == "string":
                        pdst = getattr(dst, pname)
                        for v in psrc:
                            pdst.append(v)

                    elif is_custom_type(vtyp):
                        pdst = getattr(dst, pname)
                        Dst = getattr(capa.render.proto.capa_pb2, get_type_name(vtyp))
                        for psrcv in psrc:
                            pdst = Dst()
                            translate_to_pb2(schema, vtyp, psrcv, pdst)
                            getattr(dst, pname).append(pdst)

                    else:
                        raise NotImplementedError(get_type_name(vtyp))

                # TODO: move tuple out of primitives
                elif is_tuple(ptyp):
                    raise NotImplementedError("tuple")

                else:
                    raise NotImplementedError(ptyp["type"])

            elif is_custom_type(ptyp):
                ptyp = schema["definitions"][get_type_name(ptyp)]

                Dst = getattr(capa.render.proto.capa_pb2, get_type_name(ptyp))
                pdst = Dst()

                translate_to_pb2(schema, ptyp, psrc, pdst)

                # you can't just assign to a non-initialized composite field.
                #
                # https://stackoverflow.com/a/22771612/87207
                getattr(dst, pname).CopyFrom(pdst)

            elif is_enum(ptyp):
                # like: AddressType
                Enum = getattr(capa.render.proto.capa_pb2, get_type_name(ptyp))
                # like: AddressType.ADDRESSTYPE_ABSOLUTE
                v = getattr(Enum, get_enum_value_name(ptyp, psrc.value))

                setattr(dst, pname, v)

            elif is_tuple(ptyp):
                raise NotImplementedError("tuple")

            elif is_union(ptyp):
                # in this scenario, we have a field that can be one of several types.
                # in the proto message, we set *one* of many disjoint fields.
                # they are named v0, v1, v2, etc. and not named after the type.
                # so, we need to match up the types and resolve the destination field name.
                # it is guaranteed that of the candidate fields, they each have a unique type.

                # 1. resolve the name of the source type
                ptypname = None
                for candidate_type in ptyp["anyOf"]:
                    logger.debug("candidate: %s", get_type_name(candidate_type))

                    if get_type_name(candidate_type) == "Integer" and isinstance(psrc, int):
                        # special handling of numbers to account for range
                        ptypname = "Integer"

                if not ptypname:
                    raise NotImplementedError(ptyp)

                pdstname = None
                for candidate_descriptor in dst.DESCRIPTOR.oneofs_by_name[pname].fields:
                    if candidate_descriptor.type == 11:
                        if candidate_descriptor.message_type.full_name == ptypname:
                            pdstname = candidate_descriptor.name
                            break

                    else:
                        raise NotImplementedError(candidate_descriptor.type)

                if not pdstname:
                    raise NotImplementedError(ptypname)
                    
                if ptypname == "Integer":
                    getattr(dst, pdstname).CopyFrom(int_to_pb2(psrc))

                else:
                    raise NotImplementedError(type(psrc))

            else:
                raise NotImplementedError(get_type_name(ptyp))

    else:
        raise NotImplementedError(get_type_name(typ))
