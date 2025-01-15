# Copyright 2020 Google LLC
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


from capa.ida.plugin import CapaExplorerPlugin


def PLUGIN_ENTRY():
    """mandatory entry point for IDAPython plugins

    copy this script to your IDA plugins directory and start the plugin by navigating to Edit > Plugins in IDA Pro
    """
    return CapaExplorerPlugin()
