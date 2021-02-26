import capa.features.insn

from fixtures import pma16_01_extractor, get_function, extract_function_features


def test_function_id_alloca_probe(pma16_01_extractor):
    assert pma16_01_extractor.is_library_function(0x403970) == True
    assert pma16_01_extractor.get_function_name(0x403970) == "__alloca_probe"


def test_function_id_spawnlp(pma16_01_extractor):
    # 0x405714 is __spawnlp which requires recursive match of __spawnvp at 0x407FAB 
    # (and __spawnvpe at 0x409DE8)
    assert pma16_01_extractor.is_library_function(0x405714) == True
    assert pma16_01_extractor.get_function_name(0x405714) == "__spawnlp"


def test_function_id_api_feature(pma16_01_extractor):
    f = get_function(pma16_01_extractor, 0x4011D0)
    features = extract_function_features(pma16_01_extractor, f)
    assert capa.features.insn.API("__alloca_probe") in features