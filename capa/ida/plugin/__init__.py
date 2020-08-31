# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging

import idaapi

from capa.ida.helpers import is_supported_file_type, is_supported_ida_version
from capa.ida.plugin.form import CapaExplorerForm

logger = logging.getLogger("capa")


class CapaExplorerPlugin(idaapi.plugin_t):

    # Mandatory definitions
    PLUGIN_NAME = "capa explorer"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_AUTHORS = ""

    wanted_name = PLUGIN_NAME
    comment = "IDA plugin for capa analysis framework"
    version = ""
    website = ""
    help = ""
    wanted_hotkey = ""
    flags = 0

    def __init__(self):
        """ """
        self.form = None

    def init(self):
        """
        called when IDA is loading the plugin
        """
        logging.basicConfig(level=logging.INFO)

        # check IDA version and database compat
        if not is_supported_ida_version():
            return idaapi.PLUGIN_SKIP
        if not is_supported_file_type():
            return idaapi.PLUGIN_SKIP

        logger.info("plugin initialized.")

        return idaapi.PLUGIN_KEEP

    def term(self):
        """
        called when IDA is unloading the plugin
        """
        logger.info("plugin closed.")

    def run(self, arg):
        """
        called when IDA is running the plugin as a script
        """
        self.form = CapaExplorerForm(self.PLUGIN_NAME)
        self.form.Show()
        return True
