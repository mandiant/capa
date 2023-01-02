# run this script from within IDA with ./tests/data/mimikatz.exe open
import sys
import logging
import os.path
import binascii
import traceback

import pytest

try:
    sys.path.append(os.path.dirname(__file__))
    import fixtures
    from fixtures import *
finally:
    sys.path.pop()


logger = logging.getLogger("test_ida_features")


def check_input_file(wanted):
    import idautils

    # some versions (7.4) of IDA return a truncated version of the MD5.
    # https://github.com/idapython/bin/issues/11
    try:
        found = idautils.GetInputFileMD5()[:31].decode("ascii").lower()
    except UnicodeDecodeError:
        # in IDA 7.5 or so, GetInputFileMD5 started returning raw binary
        # rather than the hex digest
        found = binascii.hexlify(idautils.GetInputFileMD5()[:15]).decode("ascii").lower()

    if not wanted.startswith(found):
        raise RuntimeError("please run the tests against sample with MD5: `%s`" % (wanted))


def get_ida_extractor(_path):
    check_input_file("5f66b82558ca92e54e77f216ef4c066c")

    # have to import this inline so pytest doesn't bail outside of IDA
    import capa.features.extractors.ida.extractor

    return capa.features.extractors.ida.extractor.IdaFeatureExtractor()


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_ida_features():
    for (sample, scope, feature, expected) in fixtures.FEATURE_PRESENCE_TESTS + fixtures.FEATURE_PRESENCE_TESTS_IDA:
        id = fixtures.make_test_id((sample, scope, feature, expected))

        try:
            check_input_file(fixtures.get_sample_md5_by_name(sample))
        except RuntimeError:
            print("SKIP %s" % (id))
            continue

        scope = fixtures.resolve_scope(scope)
        sample = fixtures.resolve_sample(sample)

        try:
            fixtures.do_test_feature_presence(get_ida_extractor, sample, scope, feature, expected)
        except Exception as e:
            print("FAIL %s" % (id))
            traceback.print_exc()
        else:
            print("OK   %s" % (id))


@pytest.mark.skip(reason="IDA Pro tests must be run within IDA")
def test_ida_feature_counts():
    for (sample, scope, feature, expected) in fixtures.FEATURE_COUNT_TESTS:
        id = fixtures.make_test_id((sample, scope, feature, expected))

        try:
            check_input_file(fixtures.get_sample_md5_by_name(sample))
        except RuntimeError:
            print("SKIP %s" % (id))
            continue

        scope = fixtures.resolve_scope(scope)
        sample = fixtures.resolve_sample(sample)

        try:
            fixtures.do_test_feature_count(get_ida_extractor, sample, scope, feature, expected)
        except Exception as e:
            print("FAIL %s" % (id))
            traceback.print_exc()
        else:
            print("OK   %s" % (id))


if __name__ == "__main__":
    print("-" * 80)

    # invoke all functions in this module that start with `test_`
    for name in dir(sys.modules[__name__]):
        if not name.startswith("test_"):
            continue

        test = getattr(sys.modules[__name__], name)
        logger.debug("invoking test: %s", name)
        sys.stderr.flush()
        test()

    print("DONE")
