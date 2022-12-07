# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import idaapi


class CapaExplorerIdaHooks(idaapi.UI_Hooks):
    def __init__(self, screen_ea_changed_hook, action_hooks):
        """facilitate IDA UI hooks

        @param screen_ea_changed_hook: function hook for IDA screen ea changed
        @param action_hooks: dict of IDA action handles
        """
        super().__init__()

        self.screen_ea_changed_hook = screen_ea_changed_hook
        self.process_action_hooks = action_hooks
        self.process_action_handle = None
        self.process_action_meta = {}

    def preprocess_action(self, name):
        """called prior to action completed

        @param name: name of action defined by idagui.cfg

        @retval must be 0
        """
        self.process_action_handle = self.process_action_hooks.get(name, None)

        if self.process_action_handle:
            self.process_action_handle(self.process_action_meta)

        # must return 0 for IDA
        return 0

    def postprocess_action(self):
        """called after action completed"""
        if not self.process_action_handle:
            return

        self.process_action_handle(self.process_action_meta, post=True)
        self.reset()

    def screen_ea_changed(self, curr_ea, prev_ea):
        """called after screen location is changed

        @param curr_ea: current location
        @param prev_ea: prev location
        """
        self.screen_ea_changed_hook(idaapi.get_current_widget(), curr_ea, prev_ea)

    def reset(self):
        """reset internal state"""
        self.process_action_handle = None
        self.process_action_meta.clear()
