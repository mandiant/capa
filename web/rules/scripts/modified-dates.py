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

import os
import sys
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

start_dir = Path(sys.argv[1])
output_file = Path(sys.argv[2])

assert start_dir.exists(), "start directory must exist"


def get_yml_files_and_dates(start_dir: Path):
    yml_files = []
    for root, _, files in os.walk(start_dir):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                file_path = Path(root) / file

                proc = subprocess.run(
                    [
                        "git",
                        "log",
                        "-1",  # only show most recent commit
                        '--pretty="%ct"',  # unix timestmp, https://git-scm.com/docs/pretty-formats#Documentation/pretty-formats.txt-emctem
                        file,  # just the filename, will run from the containing directory
                    ],
                    cwd=root,  # the directory with the file we're inspecting
                    check=True,
                    capture_output=True,
                )

                last_modified_date = int(proc.stdout.decode("utf-8").partition("\n")[0].strip('"'))

                yml_files.append((file_path, last_modified_date))
    return yml_files


yml_files_and_dates = get_yml_files_and_dates(start_dir)

yml_files_and_dates.sort(key=lambda x: x[1], reverse=True)


current_date = datetime.now()

categories = [
    ("modified in the last day", current_date - timedelta(days=1)),
    ("modified in the last week", current_date - timedelta(days=7)),
    ("modified in the last month", current_date - timedelta(days=30)),
    ("modified in the last three months", current_date - timedelta(days=90)),
    ("modified in the last year", current_date - timedelta(days=365)),
]


def write_category(f, category_name, files):
    f.write(f"=== {category_name} ===\n")
    for file_path, last_modified_date in files:
        last_modified_date_str = datetime.fromtimestamp(last_modified_date).strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{file_path} {last_modified_date_str}\n")
    f.write("\n")


with output_file.open("wt", encoding="utf-8") as f:
    for title, delta in categories:
        current_files = []
        for file_path, last_modified_date in yml_files_and_dates:
            last_modified_date_dt = datetime.fromtimestamp(last_modified_date)
            if last_modified_date_dt > delta:
                current_files.append((file_path, last_modified_date))

        write_category(f, title, current_files)

        for item in current_files:
            yml_files_and_dates.remove(item)

    write_category(f, "older", yml_files_and_dates)


logger.info("File names and modification dates have been written to %s", output_file)
