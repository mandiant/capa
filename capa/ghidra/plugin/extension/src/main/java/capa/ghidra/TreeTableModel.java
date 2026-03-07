package capa.ghidra;

import javax.swing.tree.TreeModel;

/**
 * TreeTableModel - extends TreeModel to add table column support.
 * Required by JTreeTable.
 */
public interface TreeTableModel extends TreeModel {

    /** Marker class used as the column class for the tree column. */
    class TreeTableModelMarker {}

    int getColumnCount();

    String getColumnName(int column);

    Class<?> getColumnClass(int column);

    Object getValueAt(Object node, int column);

    boolean isCellEditable(Object node, int column);

    void setValueAt(Object aValue, Object node, int column);
}