# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import subprocess
from pathlib import Path

# When the script gets executed as a standalone executable (via PyInstaller), `import binaryninja` does not work because
# we have excluded the binaryninja module in `pyinstaller.spec`. The trick here is to call the system Python and try
# to find out the path of the binaryninja module that has been installed.
# Note, including the binaryninja module in the `pyintaller.spec` would not work, since the binaryninja module tries to
# find the binaryninja core e.g., `libbinaryninjacore.dylib`, using a relative path. And this does not work when the
# binaryninja module is extracted by the PyInstaller.
code = r"""
from pathlib import Path
from importlib import util
spec = util.find_spec('binaryninja')
if spec is not None:
    if len(spec.submodule_search_locations) > 0:
            path = Path(spec.submodule_search_locations[0])
            # encode the path with utf8 then convert to hex, make sure it can be read and restored properly
            print(str(path.parent).encode('utf8').hex())
"""


def find_binja_path() -> Path:
    raw_output = subprocess.check_output(["python", "-c", code]).decode("ascii").strip()
    return Path(bytes.fromhex(raw_output).decode("utf8"))


if __name__ == "__main__":
    print(find_binja_path())
