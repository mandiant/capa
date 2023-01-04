# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging

import idaapi
import ida_kernwin

from capa.ida.plugin.form import CapaExplorerForm
from capa.ida.plugin.icon import ICON

logger = logging.getLogger(__name__)


class CapaExplorerPlugin(idaapi.plugin_t):

    # Mandatory definitions
    PLUGIN_NAME = "FLARE capa explorer"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_AUTHORS = "michael.hunhoff@mandiant.com, william.ballenthin@mandiant.com, moritz.raabe@mandiant.com"

    wanted_name = PLUGIN_NAME
    wanted_hotkey = "ALT-F5"
    comment = "IDA Pro plugin for the FLARE team's capa tool to identify capabilities in executable files."
    website = "https://github.com/mandiant/capa"
    help = "See https://github.com/mandiant/capa/blob/master/doc/usage.md"
    version = ""
    flags = 0

    def __init__(self):
        """initialize plugin"""
        self.form = None

    def init(self):
        """called when IDA is loading the plugin"""
        logging.basicConfig(level=logging.INFO)

        import capa.ida.helpers

        # do not load plugin if IDA version/file type not supported
        if not capa.ida.helpers.is_supported_ida_version():
            return idaapi.PLUGIN_SKIP
        if not capa.ida.helpers.is_supported_file_type():
            return idaapi.PLUGIN_SKIP
        if not capa.ida.helpers.is_supported_arch_type():
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def term(self):
        """called when IDA is unloading the plugin"""
        pass

    def run(self, arg):
        """
        called when IDA is running the plugin as a script

        args:
          arg (int): bitflag. Setting LSB enables automatic analysis upon
          loading. The other bits are currently undefined. See `form.Options`.
        """
        self.form = CapaExplorerForm(self.PLUGIN_NAME, arg)
        return True


# set the capa plugin icon.
#
# TL;DR: temporarily install a UI hook set the icon.
#
# Long form:
#
# in the IDAPython `plugin_t` life cycle,
#   - `init` decides if a plugin should be registered
#   - `run` executes the main logic (shows the window)
#   - `term` cleans this up
#
# we want to associate an icon with the plugin action - which is created by IDA.
# however, this action is created by IDA *after* `init` is called.
# so, we can't do this in `plugin_t.init`.
# we also can't spawn a thread and do it after a delay,
#  since `ida_kernwin.update_action_icon` must be called from the main thread.
# so we need to register a callback that's invoked from the main thread after the plugin is registered.
#
# after a lot of guess-and-check, we can use `UI_Hooks.updated_actions` to
#  receive notifications after IDA has created an action for each plugin.
# so, create this hook, wait for capa plugin to load, set the icon, and unhook.


class OnUpdatedActionsHook(ida_kernwin.UI_Hooks):
    """register a callback to be invoked each time the UI actions are updated"""

    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def updated_actions(self):
        if self.cb():
            # uninstall the callback once its run successfully
            self.unhook()


def install_icon():
    plugin_name = CapaExplorerPlugin.PLUGIN_NAME
    action_name = "Edit/Plugins/" + plugin_name

    if action_name not in ida_kernwin.get_registered_actions():
        # keep the hook registered
        return False

    # resource leak here. need to call `ida_kernwin.free_custom_icon`?
    # however, since we're not cycling this icon a lot, its probably ok.
    # expect to leak exactly one icon per application load.
    icon = ida_kernwin.load_custom_icon(data=ICON)

    ida_kernwin.update_action_icon(action_name, icon)

    # uninstall the hook
    return True


h = OnUpdatedActionsHook(install_icon)
h.hook()
