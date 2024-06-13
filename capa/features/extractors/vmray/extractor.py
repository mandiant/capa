from typing import Dict
from pathlib import Path

import pydantic_xml

from capa.features.extractors.vmray.models import Analysis
from capa.features.extractors.base_extractor import SampleHashes, DynamicFeatureExtractor

# TODO also/or look into xmltodict?


class VMRayExtractor(DynamicFeatureExtractor):
    def __init__(self, report: Path): ...

    @classmethod
    def from_report(cls, report: Path) -> "VMRayExtractor":
        print(report.read_text()[:200])

        vr = Analysis.from_xml(report.read_text())

        print(vr)


if __name__ == "__main__":
    import sys

    input_path = Path(sys.argv[1])
    VMRayExtractor.from_report(input_path)
