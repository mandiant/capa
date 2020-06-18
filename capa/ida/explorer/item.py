import binascii
import codecs
import sys

from PyQt5 import QtCore

import idaapi
import idc

import capa.ida.helpers


def info_to_name(s):
    ''' '''
    try:
        return s.split('(')[1].rstrip(')')
    except IndexError:
        return ''


def ea_to_hex_str(ea):
    ''' '''
    return '%08X' % ea


class CapaExplorerDataItem(object):
    ''' store data for CapaExplorerDataModel

        TODO
    '''
    def __init__(self, parent, data):
        ''' '''
        self._parent = parent
        self._data = data
        self._children = []
        self._checked = False

        self.flags = (QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsTristate | QtCore.Qt.ItemIsUserCheckable)

        if self._parent:
            self._parent.appendChild(self)

    def setIsEditable(self, isEditable=False):
        ''' modify item flags to be editable or not '''
        if isEditable:
            self.flags |= QtCore.Qt.ItemIsEditable
        else:
            self.flags &= ~QtCore.Qt.ItemIsEditable

    def setChecked(self, checked):
        ''' set item as checked '''
        self._checked = checked

    def isChecked(self):
        ''' get item is checked '''
        return self._checked

    def appendChild(self, item):
        ''' add child item

            @param item: CapaExplorerDataItem*
        '''
        self._children.append(item)

    def child(self, row):
        ''' get child row

            @param row: TODO
        '''
        return self._children[row]

    def childCount(self):
        ''' get child count '''
        return len(self._children)

    def columnCount(self):
        ''' get column count '''
        return len(self._data)

    def data(self, column):
        ''' get data at column '''
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self):
        ''' get parent '''
        return self._parent

    def row(self):
        ''' get row location '''
        if self._parent:
            return self._parent._children.index(self)
        return 0

    def setData(self, column, value):
        ''' set data in column '''
        self._data[column] = value

    def children(self):
        ''' yield children '''
        for child in self._children:
            yield child

    def removeChildren(self):
        ''' '''
        del self._children[:]

    def __str__(self):
        ''' get string representation of columns '''
        return ' '.join([data for data in self._data if data])

    @property
    def info(self):
        ''' '''
        return self._data[0]

    @property
    def ea(self):
        ''' '''
        try:
            return int(self._data[1], 16)
        except ValueError:
            return None

    @property
    def details(self):
        ''' '''
        return self._data[2]


class CapaExplorerRuleItem(CapaExplorerDataItem):
    ''' store data relevant to capa function result '''

    view_fmt = '%s (%d)'

    def __init__(self, parent, name, count, definition):
        ''' '''
        self._definition = definition
        name = CapaExplorerRuleItem.view_fmt % (name, count) if count else name
        super(CapaExplorerRuleItem, self).__init__(parent, [name, '', ''])

    @property
    def definition(self):
        ''' '''
        return self._definition


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    ''' store data relevant to capa function result '''

    view_fmt = 'function(%s)'

    def __init__(self, parent, name, ea):
        ''' '''
        address = ea_to_hex_str(ea)
        name = CapaExplorerFunctionItem.view_fmt % name

        super(CapaExplorerFunctionItem, self).__init__(parent, [name, address, ''])

    @property
    def info(self):
        ''' '''
        info = super(CapaExplorerFunctionItem, self).info
        name = info_to_name(info)
        return name if name else info

    @info.setter
    def info(self, name):
        ''' '''
        self._data[0] = CapaExplorerFunctionItem.view_fmt % name


class CapaExplorerBlockItem(CapaExplorerDataItem):
    ''' store data relevant to capa basic block results '''

    view_fmt = 'basic block(loc_%s)'

    def __init__(self, parent, ea):
        ''' '''
        address = ea_to_hex_str(ea)
        name = CapaExplorerBlockItem.view_fmt % address

        super(CapaExplorerBlockItem, self).__init__(parent, [name, address, ''])


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    ''' store data relevant to capa default result '''

    def __init__(self, parent, name, ea=None):
        ''' '''
        if ea:
            address = ea_to_hex_str(ea)
        else:
            address = ''

        super(CapaExplorerDefaultItem, self).__init__(parent, [name, address, ''])


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    ''' store data relevant to capa feature result '''

    def __init__(self, parent, data):
        super(CapaExplorerFeatureItem, self).__init__(parent, data)


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):

    def __init__(self, parent, name, ea):
        ''' '''
        details = capa.ida.helpers.get_disasm_line(ea)
        address = ea_to_hex_str(ea)

        super(CapaExplorerInstructionViewItem, self).__init__(parent, [name, address, details])

        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):

    def __init__(self, parent, name, ea):
        ''' '''
        address = ea_to_hex_str(ea)

        byte_snap = idaapi.get_bytes(ea, 32)
        if byte_snap:
            byte_snap = codecs.encode(byte_snap, 'hex').upper()
            # TODO: better way?
            if sys.version_info >= (3, 0):
                details = ' '.join([byte_snap[i:i + 2].decode() for i in range(0, len(byte_snap), 2)])
            else:
                details = ' '.join([byte_snap[i:i + 2] for i in range(0, len(byte_snap), 2)])
        else:
            details = ''

        super(CapaExplorerByteViewItem, self).__init__(parent, [name, address, details])

        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)


class CapaExplorerStringViewItem(CapaExplorerFeatureItem):

    def __init__(self, parent, name, ea, value):
        ''' '''
        address = ea_to_hex_str(ea)

        super(CapaExplorerStringViewItem, self).__init__(parent, [name, address, value])

        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)
