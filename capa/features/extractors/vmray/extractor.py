from typing import Dict
from pathlib import Path

import pydantic_xml

import capa.helpers
from capa.features.extractors.vmray.models import Analysis, SummaryV2
from capa.features.extractors.base_extractor import SampleHashes, DynamicFeatureExtractor

# TODO also/or look into xmltodict?


class VMRayExtractor(DynamicFeatureExtractor):
    def __init__(self, report: Path): ...

    @classmethod
    def from_report(cls, report: Path) -> "VMRayExtractor":
        print(report.read_text()[:200])

        vr = Analysis.from_xml(report.read_text())

        print(vr)

    @classmethod
    def from_summary(cls, sv2_path: Path):
        sv2_json = capa.helpers.load_json_from_path(sv2_path)
        sv2 = SummaryV2.model_validate(sv2_json)

        for k, v in sv2.files.items():
            if not v.is_sample:
                continue

            if not v.ref_static_data:
                continue

            static_data = sv2.static_data.get(v.ref_static_data.path[1])

            print(f"file_type: {static_data.pe.basic_info.file_type}")
            print(f"image_base: {hex(static_data.pe.basic_info.image_base)}")
            print(f"machine_type: {static_data.pe.basic_info.machine_type}")

            if not static_data.pe:
                continue

            pe = static_data.pe

            if pe.exports:
                print("exports")
                for export in pe.exports:
                    print(f"\tname: {export.api.name}, address: {hex(export.address)}")

            if pe.imports:
                print("imports")
                for import_ in pe.imports:
                    print(f"\tdll: {import_.dll} ({len(import_.apis)})")

if __name__ == "__main__":
    import sys

    input_path = Path(sys.argv[1])

    VMRayExtractor.from_report(input_path)
    # VMRayExtractor.from_summary(input_path)
