from fixtures import get_function, pma16_01_extractor, extract_function_features

import capa.features.insn


def test_function_id_simple_match(pma16_01_extractor):
    assert pma16_01_extractor.is_library_function(0x407490) == True
    assert pma16_01_extractor.get_function_name(0x407490) == "__aulldiv"


def test_function_id_gz_pat(pma16_01_extractor):
    # aullrem is stored in `test_aullrem.pat.gz`
    assert pma16_01_extractor.is_library_function(0x407500) == True
    assert pma16_01_extractor.get_function_name(0x407500) == "__aullrem"


def test_function_id_complex_match(pma16_01_extractor):
    # 0x405714 is __spawnlp which requires recursive match of __spawnvp at 0x407FAB
    # (and __spawnvpe at 0x409DE8)
    assert pma16_01_extractor.is_library_function(0x405714) == True
    assert pma16_01_extractor.get_function_name(0x405714) == "__spawnlp"


def test_function_id_api_feature(pma16_01_extractor):
    f = get_function(pma16_01_extractor, 0x404548)
    features = extract_function_features(pma16_01_extractor, f)
    assert capa.features.insn.API("__aulldiv") in features
