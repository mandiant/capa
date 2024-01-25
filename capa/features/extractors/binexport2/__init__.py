"""
Proto files generated via protobuf v24.4:

    protoc --python_out=. --mypy_out=. binexport2.proto
"""
import os
import logging
from pathlib import Path

from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2


logger = logging.getLogger(__name__)


def get_binexport2(sample: Path) -> BinExport2:
    be2 = BinExport2()
    be2.ParseFromString(sample.read_bytes())
    return be2


def get_sample_from_binexport2(be2: BinExport2) -> Path:
    # $CAPA_SAMPLE_DIR/<sha256>
    base = Path(os.environ.get("CAPA_SAMPLES_DIR", "."))

    sha256 = be2.meta_information.executable_id.lower()

    logger.debug("searching for sample in: %s", base)
    path = base / sha256
    if path.exists():
        return path
    else:
        raise ValueError("cannot find sample")
