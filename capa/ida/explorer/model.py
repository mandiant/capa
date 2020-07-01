from PyQt5 import QtCore, QtGui, Qt
from collections import deque

import capa.render.utils as rutils

import idaapi
import idc

from capa.ida.explorer.item import (
    CapaExplorerDataItem,
    CapaExplorerDefaultItem,
    CapaExplorerFunctionItem,
    CapaExplorerRuleItem,
    CapaExplorerStringViewItem,
    CapaExplorerInstructionViewItem,
    CapaExplorerByteViewItem,
    CapaExplorerBlockItem,
    CapaExplorerRuleMatchItem,
    CapaExplorerFeatureItem
)

import capa.ida.helpers

# default highlight color used in IDA window
DEFAULT_HIGHLIGHT = 0xD096FF


class CapaExplorerDataModel(QtCore.QAbstractItemModel):
    """ """

    COLUMN_INDEX_RULE_INFORMATION = 0
    COLUMN_INDEX_VIRTUAL_ADDRESS = 1
    COLUMN_INDEX_DETAILS = 2

    COLUMN_COUNT = 3

    def __init__(self, parent=None):
        """ """
        super(CapaExplorerDataModel, self).__init__(parent)
        self.root_node = CapaExplorerDataItem(None, ['Rule Information', 'Address', 'Details'])

    def reset(self):
        """ """
        # reset checkboxes and color highlights
        # TODO: make less hacky
        for idx in range(self.root_node.childCount()):
            root_index = self.index(idx, 0, QtCore.QModelIndex())
            for model_index in self.iterateChildrenIndexFromRootIndex(root_index, ignore_root=False):
                model_index.internalPointer().setChecked(False)
                self.util_reset_ida_highlighting(model_index.internalPointer(), False)
                self.dataChanged.emit(model_index, model_index)

    def clear(self):
        """ """
        self.beginResetModel()
        self.root_node.removeChildren()
        self.endResetModel()

    def columnCount(self, model_index):
        """ get the number of columns for the children of the given parent

            @param model_index: QModelIndex*

            @retval column count
        """
        if model_index.isValid():
            return model_index.internalPointer().columnCount()
        else:
            return self.root_node.columnCount()

    def data(self, model_index, role):
        """ get data stored under the given role for the item referred to by the index

            @param model_index: QModelIndex*
            @param role: QtCore.Qt.*

            @retval data to be displayed
        """
        if not model_index.isValid():
            return None

        item = model_index.internalPointer()
        column = model_index.column()

        if role == QtCore.Qt.DisplayRole:
            # display data in corresponding column
            return item.data(column)

        if role == QtCore.Qt.ToolTipRole and isinstance(item, (CapaExplorerRuleItem, CapaExplorerRuleMatchItem)) and \
                CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column:
            # show tooltip containing rule source
            return item.source

        if role == QtCore.Qt.CheckStateRole and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # inform view how to display content of checkbox - un/checked
            return QtCore.Qt.Checked if item.isChecked() else QtCore.Qt.Unchecked

        if role == QtCore.Qt.FontRole and column in (CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS,
                                                     CapaExplorerDataModel.COLUMN_INDEX_DETAILS):
            # set font for virtual address and details columns
            font = QtGui.QFont('Courier', weight=QtGui.QFont.Medium)
            if column == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS:
                font.setBold(True)
            return font

        if role == QtCore.Qt.FontRole and isinstance(item, (CapaExplorerRuleItem, CapaExplorerRuleMatchItem,
                                                            CapaExplorerBlockItem, CapaExplorerFunctionItem,
                                                            CapaExplorerFeatureItem)) and \
                column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # set bold font for top-level rules
            font = QtGui.QFont()
            font.setBold(True)
            return font

        if role == QtCore.Qt.ForegroundRole and column == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS:
            # set color for virtual address column
            return QtGui.QColor(88, 139, 174)

        if role == QtCore.Qt.ForegroundRole and isinstance(item, CapaExplorerFeatureItem) and column == \
                CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # set color for feature items
            return QtGui.QColor(79, 121, 66)

        return None

    def flags(self, model_index):
        """ get item flags for given index

            @param model_index: QModelIndex*

            @retval QtCore.Qt.ItemFlags
        """
        if not model_index.isValid():
            return QtCore.Qt.NoItemFlags

        return model_index.internalPointer().flags

    def headerData(self, section, orientation, role):
        """ get data for the given role and section in the header with the specified orientation

            @param section: int
            @param orientation: QtCore.Qt.Orientation
            @param role: QtCore.Qt.DisplayRole

            @retval header data list()
        """
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.root_node.data(section)

        return None

    def index(self, row, column, parent):
        """ get index of the item in the model specified by the given row, column and parent index

            @param row: int
            @param column: int
            @param parent: QModelIndex*

            @retval QModelIndex*
        """
        if not self.hasIndex(row, column, parent):
            return QtCore.QModelIndex()

        if not parent.isValid():
            parent_item = self.root_node
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)

        if child_item:
            return self.createIndex(row, column, child_item)
        else:
            return QtCore.QModelIndex()

    def parent(self, model_index):
        """ get parent of the model item with the given index

            if the item has no parent, an invalid QModelIndex* is returned

            @param model_index: QModelIndex*

            @retval QModelIndex*
        """
        if not model_index.isValid():
            return QtCore.QModelIndex()

        child = model_index.internalPointer()
        parent = child.parent()

        if parent == self.root_node:
            return QtCore.QModelIndex()

        return self.createIndex(parent.row(), 0, parent)

    def iterateChildrenIndexFromRootIndex(self, model_index, ignore_root=True):
        """ depth-first traversal of child nodes

            @param model_index: QModelIndex*
            @param ignore_root: if set, do not return root index

            @retval yield QModelIndex*
        """
        visited = set()
        stack = deque((model_index,))

        while True:
            try:
                child_index = stack.pop()
            except IndexError:
                break

            if child_index not in visited:
                if not ignore_root or child_index is not model_index:
                    # ignore root
                    yield child_index

                visited.add(child_index)

                for idx in range(self.rowCount(child_index)):
                    stack.append(child_index.child(idx, 0))

    def util_reset_ida_highlighting(self, item, checked):
        """ """
        if not isinstance(item, (CapaExplorerStringViewItem, CapaExplorerInstructionViewItem,
                                 CapaExplorerByteViewItem)):
            # ignore other item types
            return

        curr_highlight = idc.get_color(item.location, idc.CIC_ITEM)

        if checked:
            # item checked - record current highlight and set to new
            item.ida_highlight = curr_highlight
            idc.set_color(item.location, idc.CIC_ITEM, DEFAULT_HIGHLIGHT)
        else:
            # item unchecked - reset highlight
            if curr_highlight != DEFAULT_HIGHLIGHT:
                # user modified highlight - record new highlight and do not modify
                item.ida_highlight = curr_highlight
            else:
                # reset highlight to previous
                idc.set_color(item.location, idc.CIC_ITEM, item.ida_highlight)

    def setData(self, model_index, value, role):
        """ set the role data for the item at index to value

            @param model_index: QModelIndex*
            @param value: QVariant*
            @param role: QtCore.Qt.EditRole

            @retval True/False
        """
        if not model_index.isValid():
            return False

        if role == QtCore.Qt.CheckStateRole and model_index.column() ==\
                CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # user un/checked box - un/check parent and children
            for child_index in self.iterateChildrenIndexFromRootIndex(model_index, ignore_root=False):
                child_index.internalPointer().setChecked(value)
                self.util_reset_ida_highlighting(child_index.internalPointer(), value)
                self.dataChanged.emit(child_index, child_index)
            return True

        if role == QtCore.Qt.EditRole and value and \
                model_index.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION and \
                isinstance(model_index.internalPointer(), CapaExplorerFunctionItem):
            # user renamed function - update IDA database and data model
            old_name = model_index.internalPointer().info
            new_name = str(value)

            if idaapi.set_name(model_index.internalPointer().location, new_name):
                # success update IDA database - update data model
                self.update_function_name(old_name, new_name)
                return True

        # no handle
        return False

    def rowCount(self, model_index):
        """ get the number of rows under the given parent

            when the parent is valid it means that is returning the number of
            children of parent

            @param model_index: QModelIndex*

            @retval row count
        """
        if model_index.column() > 0:
            return 0

        if not model_index.isValid():
            item = self.root_node
        else:
            item = model_index.internalPointer()

        return item.childCount()

    def render_capa_doc_statement_node(self, parent, statement, doc):
        """ render capa statement read from doc

            @param parent: parent to which new child is assigned
            @param statement: statement read from doc
            @param doc: capa result doc

            "statement": {
                "type": "or"
            },
        """
        if statement['type'] in ('and', 'or', 'optional'):
            return CapaExplorerDefaultItem(parent, statement['type'])
        elif statement['type'] == 'not':
            # TODO: do we display 'not'
            pass
        elif statement['type'] == 'some':
            return CapaExplorerDefaultItem(parent, statement['count'] + ' or more')
        elif statement['type'] == 'range':
            # `range` is a weird node, its almost a hybrid of statement + feature.
            # it is a specific feature repeated multiple times.
            # there's no additional logic in the feature part, just the existence of a feature.
            # so, we have to inline some of the feature rendering here.
            display = 'count(%s): ' % self.capa_doc_feature_to_display(statement['child'])

            if statement['max'] == statement['min']:
                display += '%d' % (statement['min'])
            elif statement['min'] == 0:
                display += '%d or fewer' % (statement['max'])
            elif statement['max'] == (1 << 64 - 1):
                display += '%d or more' % (statement['min'])
            else:
                display += 'between %d and %d' % (statement['min'], statement['max'])

            return CapaExplorerFeatureItem(parent, display=display)
        elif statement['type'] == 'subscope':
            return CapaExplorerFeatureItem(parent, 'subscope(%s)' % statement['subscope'])
        elif statement['type'] == 'regex':
            # regex is a `Statement` not a `Feature`
            # this is because it doesn't get extracted, but applies to all strings in scope.
            # so we have to handle it here
            return CapaExplorerFeatureItem(parent, 'regex(%s)' % statement['pattern'], details=statement['match'])
        else:
            raise RuntimeError('unexpected match statement type: ' + str(statement))

    def render_capa_doc_match(self, parent, match, doc):
        """ render capa match read from doc

            @param parent: parent node to which new child is assigned
            @param match: match read from doc
            @param doc: capa result doc

            "matches": {
                "0": {
                    "children": [],
                    "locations": [
                        4317184
                    ],
                    "node": {
                        "feature": {
                            "section": ".rsrc",
                            "type": "section"
                        },
                        "type": "feature"
                    },
                    "success": true
                }
            },
        """
        if not match['success']:
            # TODO: display failed branches at some point? Help with debugging rules?
            return

        # optional statement with no successful children is empty
        if (match['node'].get('statement', {}).get('type') == 'optional'
                and not any(map(lambda m: m['success'], match['children']))):
            return

        if match['node']['type'] == 'statement':
            parent2 = self.render_capa_doc_statement_node(parent, match['node']['statement'], doc)
        elif match['node']['type'] == 'feature':
            parent2 = self.render_capa_doc_feature_node(parent, match['node']['feature'], match['locations'], doc)
        else:
            raise RuntimeError('unexpected node type: ' + str(match['node']['type']))

        for child in match['children']:
            self.render_capa_doc_match(parent2, child, doc)

    def render_capa_doc(self, doc):
        """ render capa features specified in doc

            @param doc: capa result doc
        """
        self.beginResetModel()

        for rule in rutils.capability_rules(doc):
            parent = CapaExplorerRuleItem(self.root_node, rule['meta']['name'], len(rule['matches']), rule['source'])

            for (location, match) in doc[rule['meta']['name']]['matches'].items():
                if rule['meta']['scope'] == capa.rules.FILE_SCOPE:
                    parent2 = parent
                elif rule['meta']['scope'] == capa.rules.FUNCTION_SCOPE:
                    parent2 = CapaExplorerFunctionItem(parent, location)
                elif rule['meta']['scope'] == capa.rules.BASIC_BLOCK_SCOPE:
                    parent2 = CapaExplorerBlockItem(parent, location)
                else:
                    raise RuntimeError('unexpected rule scope: ' + str(rule['meta']['scope']))

                self.render_capa_doc_match(parent2, match, doc)

        self.endResetModel()

    def capa_doc_feature_to_display(self, feature):
        """ convert capa doc feature type string to display string for ui

            @param feature: capa feature read from doc

            "feature": {
                "number": 2147483903,
                "type": "number"
            },
        """
        mapping = {
            'string': 'string(%s)',
            'bytes': 'bytes(%s)',
            'api': 'api(%s)',
            'mnemonic': 'mnemonic(%s)',
            'export': 'export(%s)',
            'import': 'import(%s)',
            'section': 'section(%s)',
            'number': 'number(0x%X)',
            'offset': 'offset(0x%X)',
            'characteristic': 'characteristic(%s)',
            'match': 'rule match(%s)'
        }

        '''
            "feature": {
                "characteristic": [
                    "loop",
                    true
                ],
                "type": "characteristic"
            },
        '''
        if feature['type'] == 'characteristic':
            return mapping['characteristic'] % feature['characteristic'][0]

        # convert bytes feature from "410ab4" to "41 0A B4"
        if feature['type'] == 'bytes':
            return mapping['bytes'] % ' '.join(feature['bytes'][i:i + 2] for i in
                                               range(0, len(feature['bytes']), 2)).upper()

        try:
            fmt = mapping[feature['type']]
        except KeyError:
            raise RuntimeError('unexpected doc type: ' + str(feature['type']))

        return fmt % feature[feature['type']]

    def render_capa_doc_feature_node(self, parent, feature, locations, doc):
        """ """
        display = self.capa_doc_feature_to_display(feature)

        if len(locations) == 1:
            parent2 = self.render_capa_doc_feature(parent, feature, next(iter(locations)), doc, display=display)
        else:
            # feature has multiple children, nest  under one parent feature node
            parent2 = CapaExplorerFeatureItem(parent, display)

            for location in sorted(locations):
                self.render_capa_doc_feature(parent2, feature, location, doc)

        return parent2

    def render_capa_doc_feature(self, parent, feature, location, doc, display='-'):
        """ render capa feature read from doc

            @param parent: parent node to which new child is assigned
            @param feature: feature read from doc
            @param doc: capa feature doc

            "node": {
                "feature": {
                    "number": 255,
                    "type": "number"
                },
                "type": "feature"
            },

            @param location: address of feature
            @param display: text to display in plugin ui
        """
        instruction_view = (
            'bytes',
            'api',
            'mnemonic',
            'number',
            'offset'
        )
        byte_view = (
            'section',
        )
        string_view = (
            'string',
        )
        default_feature_view = (
            'import',
            'export'
        )

        # special handling for characteristic pending type
        if feature['type'] == 'characteristic':
            if feature['characteristic'][0] in ('embedded pe',):
                return CapaExplorerByteViewItem(parent, display, location)

            if feature['characteristic'][0] in ('loop', 'recursive call', 'tight loop', 'switch'):
                return CapaExplorerFeatureItem(parent, display=display)

            # default to instruction view
            return CapaExplorerInstructionViewItem(parent, display, location)

        if feature['type'] == 'match':
            return CapaExplorerRuleMatchItem(parent, display, source=doc.get(feature['match'], {}).get('source', ''))

        if feature['type'] in instruction_view:
            return CapaExplorerInstructionViewItem(parent, display, location)

        if feature['type'] in byte_view:
            return CapaExplorerByteViewItem(parent, display, location)

        if feature['type'] in string_view:
            return CapaExplorerStringViewItem(parent, display, location)

        if feature['type'] in default_feature_view:
            return CapaExplorerFeatureItem(parent, display=display)

        raise RuntimeError('unexpected feature type: ' + str(feature['type']))

    def update_function_name(self, old_name, new_name):
        """ update all instances of function name

            @param old_name: previous function name
            @param new_name: new function name
        """
        root_index = self.index(0, 0, QtCore.QModelIndex())

        # convert name to view format for matching
        old_name = CapaExplorerFunctionItem.fmt % old_name

        for model_index in self.match(root_index, QtCore.Qt.DisplayRole, old_name, hits=-1,
                                      flags=QtCore.Qt.MatchRecursive):
            if not isinstance(model_index.internalPointer(), CapaExplorerFunctionItem):
                continue

            model_index.internalPointer().info = new_name
            self.dataChanged.emit(model_index, model_index)
