import types

import capa.features.extractors.binexport2.insn


class FakeProtoMessage:
    def __init__(self, **fields):
        self._fields = fields
        for name, value in fields.items():
            setattr(self, name, value)

    def HasField(self, name: str) -> bool:
        return name in self._fields


def make_instruction_context(vertex: FakeProtoMessage, libraries: list[FakeProtoMessage]):
    be2 = types.SimpleNamespace(
        instruction=[types.SimpleNamespace(call_target=[0x401234])],
        call_graph=types.SimpleNamespace(vertex=[vertex]),
        library=libraries,
    )
    idx = types.SimpleNamespace(vertex_index_by_address={0x401234: 0})
    analysis = types.SimpleNamespace(thunks={})
    function_context = types.SimpleNamespace(ctx=types.SimpleNamespace(be2=be2, idx=idx, analysis=analysis))
    fh = types.SimpleNamespace(inner=function_context)
    ih = types.SimpleNamespace(inner=types.SimpleNamespace(instruction_index=0), address=0x401000)
    return fh, ih


def test_extract_insn_api_features_emit_library_qualified_symbols(monkeypatch):
    monkeypatch.setattr(
        capa.features.extractors.binexport2.helpers,
        "is_vertex_type",
        lambda _vertex, _vertex_type: True,
    )

    vertex = FakeProtoMessage(mangled_name="CreateFileA", library_index=0)
    library = FakeProtoMessage(name="kernel32")
    fh, ih = make_instruction_context(vertex, [library])

    features = list(capa.features.extractors.binexport2.insn.extract_insn_api_features(fh, None, ih))
    api_names = {feature.value for feature, _ in features}

    assert "CreateFileA" in api_names
    assert "CreateFile" in api_names
    assert "kernel32.CreateFileA" in api_names
    assert "kernel32.CreateFile" in api_names


def test_extract_insn_api_features_without_library_keeps_unqualified_symbols(monkeypatch):
    monkeypatch.setattr(
        capa.features.extractors.binexport2.helpers,
        "is_vertex_type",
        lambda _vertex, _vertex_type: True,
    )

    vertex = FakeProtoMessage(mangled_name="CreateFileA")
    fh, ih = make_instruction_context(vertex, [])

    features = list(capa.features.extractors.binexport2.insn.extract_insn_api_features(fh, None, ih))
    api_names = {feature.value for feature, _ in features}

    assert "CreateFileA" in api_names
    assert "CreateFile" in api_names
    assert not any(name.startswith("kernel32.") for name in api_names)


def test_extract_insn_api_features_library_without_name_keeps_unqualified_symbols(monkeypatch):
    monkeypatch.setattr(
        capa.features.extractors.binexport2.helpers,
        "is_vertex_type",
        lambda _vertex, _vertex_type: True,
    )

    vertex = FakeProtoMessage(mangled_name="CreateFileA", library_index=0)
    fh, ih = make_instruction_context(vertex, [FakeProtoMessage()])

    features = list(capa.features.extractors.binexport2.insn.extract_insn_api_features(fh, None, ih))
    api_names = {feature.value for feature, _ in features}

    assert "CreateFileA" in api_names
    assert "CreateFile" in api_names
    assert not any("." in name for name in api_names)


def test_extract_insn_api_features_invalid_library_index_keeps_unqualified_symbols(monkeypatch):
    monkeypatch.setattr(
        capa.features.extractors.binexport2.helpers,
        "is_vertex_type",
        lambda _vertex, _vertex_type: True,
    )

    vertex = FakeProtoMessage(mangled_name="CreateFileA", library_index=99)
    fh, ih = make_instruction_context(vertex, [FakeProtoMessage(name="kernel32")])

    features = list(capa.features.extractors.binexport2.insn.extract_insn_api_features(fh, None, ih))
    api_names = {feature.value for feature, _ in features}

    assert "CreateFileA" in api_names
    assert "CreateFile" in api_names
    assert not any(name.startswith("kernel32.") for name in api_names)
