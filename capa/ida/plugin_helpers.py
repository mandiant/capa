# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import logging

import idc
import idaapi
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTreeWidgetItem, QTreeWidgetItemIterator

CAPA_EXTENSION = ".capas"


logger = logging.getLogger("capa_ida")


def get_input_file(freeze=True):
    """
    get input file path

        freeze (bool): if True, get freeze file if it exists
    """
    # try original file in same directory as idb/i64 without idb/i64 file extension
    input_file = idc.get_idb_path()[:-4]

    if freeze:
        # use frozen file if it exists
        freeze_file_cand = "%s%s" % (input_file, CAPA_EXTENSION)
        if os.path.isfile(freeze_file_cand):
            return freeze_file_cand

    if not os.path.isfile(input_file):
        # TM naming
        input_file = "%s.mal_" % idc.get_idb_path()[:-4]
        if not os.path.isfile(input_file):
            input_file = idaapi.ask_file(0, "*.*", "Please specify input file.")
    if not input_file:
        raise ValueError("could not find input file")
    return input_file


def get_orig_color_feature_vas(vas):
    orig_colors = {}
    for va in vas:
        orig_colors[va] = idc.get_color(va, idc.CIC_ITEM)
    return orig_colors


def reset_colors(orig_colors):
    if orig_colors:
        for va, color in orig_colors.iteritems():
            idc.set_color(va, idc.CIC_ITEM, orig_colors[va])


def reset_selection(tree):
    iterator = QTreeWidgetItemIterator(tree, QTreeWidgetItemIterator.Checked)
    while iterator.value():
        item = iterator.value()
        item.setCheckState(0, Qt.Unchecked)  # column, state
        iterator += 1


def get_disasm_line(va):
    return idc.generate_disasm_line(va, idc.GENDSM_FORCE_CODE)


def get_selected_items(tree, skip_level_1=False):
    selected = []
    iterator = QTreeWidgetItemIterator(tree, QTreeWidgetItemIterator.Checked)
    while iterator.value():
        item = iterator.value()
        if skip_level_1:
            # hacky way to check if item is at level 1, if so, skip
            # alternative, check if text in disasm column
            if item.parent() and item.parent().parent() is None:
                iterator += 1
                continue
        if item.text(1):
            # logger.debug('selected %s, %s', item.text(0), item.text(1))
            selected.append(int(item.text(1), 0x10))
        iterator += 1
    return selected


def add_child_item(parent, values, feature=None):
    child = QTreeWidgetItem(parent)
    child.setFlags(child.flags() | Qt.ItemIsTristate | Qt.ItemIsUserCheckable)
    for i, v in enumerate(values):
        child.setText(i, v)
        if feature:
            child.setData(0, 0x100, feature)
        child.setCheckState(0, Qt.Unchecked)
    return child
