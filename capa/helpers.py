# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os

_hex = hex


def hex(i):
    # under py2.7, long integers get formatted with a trailing `L`
    # and this is not pretty. so strip it out.
    return _hex(oint(i)).rstrip("L")


def oint(i):
    # there seems to be some trouble with using `int(viv_utils.Function)`
    # with the black magic we do with binding the `__int__()` routine.
    # i haven't had a chance to debug this yet (and i have no hotel wifi).
    # so in the meantime, detect this, and call the method directly.
    try:
        return int(i)
    except TypeError:
        return i.__int__()


def get_file_taste(sample_path):
    if not os.path.exists(sample_path):
        raise IOError("sample path %s does not exist or cannot be accessed" % sample_path)
    with open(sample_path, "rb") as f:
        taste = f.read(8)
    return taste
