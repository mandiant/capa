# run this script from within IDA with ./tests/data/mimikatz.exe open
import logging
import traceback
import collections

import pytest

import capa.features
import capa.features.file
import capa.features.insn
import capa.features.basicblock

logger = logging.getLogger("test_ida_features")


def check_input_file():
    import idautils

    wanted = "5f66b82558ca92e54e77f216ef4c066c"
    # some versions of IDA return a truncated version of the MD5.
    # https://github.com/idapython/bin/issues/11
    found = idautils.GetInputFileMD5().rstrip(b"\x00").decode("ascii").lower()
    if not wanted.startswith(found):
        raise RuntimeError("please run the tests against `mimikatz.exe`")


def get_extractor():
    check_input_file()

    # have to import import this inline so pytest doesn't bail outside of IDA
    import capa.features.extractors.ida

    return capa.features.extractors.ida.IdaFeatureExtractor()


def extract_file_features():
    extractor = get_extractor()
    features = set([])
    for feature, va in extractor.extract_file_features():
        features.add(feature)
    return features


def extract_function_features(f):
    extractor = get_extractor()
    features = collections.defaultdict(set)
    for bb in extractor.get_basic_blocks(f):
        for insn in extractor.get_instructions(f, bb):
            for feature, va in extractor.extract_insn_features(f, bb, insn):
                features[feature].add(va)
        for feature, va in extractor.extract_basic_block_features(f, bb):
            features[feature].add(va)
    for feature, va in extractor.extract_function_features(f):
        features[feature].add(va)
    return features


def extract_basic_block_features(f, bb):
    extractor = get_extractor()
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(f, bb):
        for feature, va in extractor.extract_insn_features(f, bb, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(f, bb):
        features[feature].add(va)
    return features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_api_features():
    # have to import import this inline so pytest doesn't bail outside of IDA
    import idaapi

    f = idaapi.get_func(0x403BAC)
    features = extract_function_features(f)
    assert capa.features.insn.API("advapi32.CryptAcquireContextW") in features
    assert capa.features.insn.API("advapi32.CryptAcquireContext") in features
    assert capa.features.insn.API("advapi32.CryptGenKey") in features
    assert capa.features.insn.API("advapi32.CryptImportKey") in features
    assert capa.features.insn.API("advapi32.CryptDestroyKey") in features
    assert capa.features.insn.API("CryptAcquireContextW") in features
    assert capa.features.insn.API("CryptAcquireContext") in features
    assert capa.features.insn.API("CryptGenKey") in features
    assert capa.features.insn.API("CryptImportKey") in features
    assert capa.features.insn.API("CryptDestroyKey") in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_string_features():
    import idaapi

    f = idaapi.get_func(0x40105D)
    features = extract_function_features(f)
    assert capa.features.String("SCardControl") in features
    assert capa.features.String("SCardTransmit") in features
    assert capa.features.String("ACR  > ") in features
    # other strings not in this function
    assert capa.features.String("bcrypt.dll") not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_byte_features():
    import idaapi

    f = idaapi.get_func(0x40105D)
    features = extract_function_features(f)
    wanted = capa.features.Bytes("SCardControl".encode("utf-16le"))
    # use `==` rather than `is` because the result is not `True` but a truthy value.
    assert wanted.evaluate(features) == True


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_number_features():
    import idaapi

    f = idaapi.get_func(0x40105D)
    features = extract_function_features(f)
    assert capa.features.insn.Number(0xFF) in features
    assert capa.features.insn.Number(0x3136B0) in features
    # the following are stack adjustments
    assert capa.features.insn.Number(0xC) not in features
    assert capa.features.insn.Number(0x10) not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_offset_features():
    import idaapi

    f = idaapi.get_func(0x40105D)
    features = extract_function_features(f)
    assert capa.features.insn.Offset(0x0) in features
    assert capa.features.insn.Offset(0x4) in features
    assert capa.features.insn.Offset(0xC) in features
    # the following are stack references
    assert capa.features.insn.Offset(0x8) not in features
    assert capa.features.insn.Offset(0x10) not in features

    # this function has the following negative offsets
    # movzx   ecx, byte ptr [eax-1]
    # movzx   eax, byte ptr [eax-2]
    f = idaapi.get_func(0x4011FB)
    features = extract_function_features(f)
    assert capa.features.insn.Offset(-0x1) in features
    assert capa.features.insn.Offset(-0x2) in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_nzxor_features():
    import idaapi

    f = idaapi.get_func(0x410DFC)
    features = extract_function_features(f)
    assert capa.features.Characteristic("nzxor") in features  # 0x0410F0B


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_mnemonic_features():
    import idaapi

    f = idaapi.get_func(0x40105D)
    features = extract_function_features(f)
    assert capa.features.insn.Mnemonic("push") in features
    assert capa.features.insn.Mnemonic("movzx") in features
    assert capa.features.insn.Mnemonic("xor") in features

    assert capa.features.insn.Mnemonic("in") not in features
    assert capa.features.insn.Mnemonic("out") not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_file_section_name_features():
    features = extract_file_features()
    assert capa.features.file.Section(".idata") in features
    assert capa.features.file.Section(".text") in features
    assert capa.features.file.Section(".nope") not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_tight_loop_features():
    import idaapi

    extractor = get_extractor()
    f = idaapi.get_func(0x402EC4)
    for bb in extractor.get_basic_blocks(f):
        if bb.__int__() != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_tight_loop_bb_features():
    import idaapi

    extractor = get_extractor()
    f = idaapi.get_func(0x402EC4)
    for bb in extractor.get_basic_blocks(f):
        if bb.__int__() != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_file_import_name_features():
    features = extract_file_features()
    assert capa.features.file.Import("advapi32.CryptSetHashParam") in features
    assert capa.features.file.Import("CryptSetHashParam") in features
    assert capa.features.file.Import("kernel32.IsWow64Process") in features
    assert capa.features.file.Import("msvcrt.exit") in features
    assert capa.features.file.Import("cabinet.#11") in features
    assert capa.features.file.Import("#11") not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_stackstring_features():
    import idaapi

    f = idaapi.get_func(0x4556E5)
    features = extract_function_features(f)
    assert capa.features.Characteristic("stack string") in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_switch_features():
    import idaapi

    f = idaapi.get_func(0x409411)
    features = extract_function_features(f)
    assert capa.features.Characteristic("switch") in features

    f = idaapi.get_func(0x409393)
    features = extract_function_features(f)
    assert capa.features.Characteristic("switch") not in features


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_function_calls_to():
    import idaapi

    # this function is used in a function pointer
    f = idaapi.get_func(0x4011FB)
    features = extract_function_features(f)
    assert capa.features.Characteristic("calls to") not in features

    # __FindPESection is called once
    f = idaapi.get_func(0x470360)
    features = extract_function_features(f)
    assert len(features[capa.features.Characteristic("calls to")]) == 1


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_function_calls_from():
    import idaapi

    f = idaapi.get_func(0x4011FB)
    features = extract_function_features(f)
    assert capa.features.Characteristic("calls from") in features
    assert len(features[capa.features.Characteristic("calls from")]) == 3


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_basic_block_count():
    import idaapi

    f = idaapi.get_func(0x4011FB)
    features = extract_function_features(f)
    assert len(features[capa.features.basicblock.BasicBlock()]) == 15


if __name__ == "__main__":
    print("-" * 80)

    # invoke all functions in this module that start with `test_`
    for name in dir(sys.modules[__name__]):
        if not name.startswith("test_"):
            continue

        test = getattr(sys.modules[__name__], name)
        logger.debug("invoking test: %s", name)
        sys.stderr.flush()
        try:
            test()
        except AssertionError as e:
            print("FAIL %s" % (name))
            traceback.print_exc()
        else:
            print("OK   %s" % (name))
