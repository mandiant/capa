# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# import all the symbols from our fixtures
# and make available to test cases, implicitly.
# this is thanks to pytest magic.
#
# see the following for a discussion:
# https://www.revsys.com/tidbits/pytest-fixtures-are-magic/
# https://lobste.rs/s/j8xgym/pytest_fixtures_are_magic
from fixtures import *  # noqa: F403 [unable to detect undefined names]
from fixtures import _692f_dotnetfile_extractor  # noqa: F401 [imported but unused]
from fixtures import _1c444_dotnetfile_extractor  # noqa: F401 [imported but unused]
from fixtures import _039a6_dotnetfile_extractor  # noqa: F401 [imported but unused]
from fixtures import _0953c_dotnetfile_extractor  # noqa: F401 [imported but unused]
