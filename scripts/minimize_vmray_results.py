#!/usr/bin/env python
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Extract files relevant to capa analysis from VMRay Analysis Archive and create a new ZIP file.
"""
import sys
import logging
import zipfile
import argparse
from pathlib import Path

from capa.features.extractors.vmray import DEFAULT_ARCHIVE_PASSWORD, VMRayAnalysis

logger = logging.getLogger(__name__)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Minimize VMRay Analysis Archive to ZIP file only containing relevant files"
    )
    parser.add_argument(
        "analysis_archive",
        type=Path,
        help="path to VMRay Analysis Archive downloaded from Dynamic Analysis Report page",
    )
    parser.add_argument(
        "-p", "--password", type=str, default="infected", help="password used to unzip and zip protected archives"
    )
    args = parser.parse_args(args=argv)

    analysis_archive = args.analysis_archive

    vmra = VMRayAnalysis(analysis_archive)
    sv2_json = vmra.zipfile.read("logs/summary_v2.json", pwd=DEFAULT_ARCHIVE_PASSWORD)
    flog_xml = vmra.zipfile.read("logs/flog.xml", pwd=DEFAULT_ARCHIVE_PASSWORD)
    sample_file_buf = vmra.sample_file_buf
    assert vmra.sample_file_analysis is not None
    sample_sha256: str = vmra.sample_file_analysis.hash_values.sha256.lower()

    new_zip_name = f"{analysis_archive.parent / analysis_archive.stem}_min.zip"
    with zipfile.ZipFile(new_zip_name, "w") as new_zip:
        new_zip.writestr("logs/summary_v2.json", sv2_json)
        new_zip.writestr("logs/flog.xml", flog_xml)
        new_zip.writestr(f"internal/static_analyses/{sample_sha256}/objects/files/{sample_sha256}", sample_file_buf)
        new_zip.setpassword(args.password.encode("ascii"))

    # ensure capa loads the minimized archive
    assert isinstance(VMRayAnalysis(Path(new_zip_name)), VMRayAnalysis)

    print(f"Created minimized VMRay archive '{new_zip_name}' with password '{args.password}'.")


if __name__ == "__main__":
    sys.exit(main())
