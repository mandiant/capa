package capa.ghidra;

import javax.swing.tree.TreeModel;

/**
 * Interface for a model that combines a tree structure with table columns.
 * The first column is always the tree column.
 */
public interface TreeTableModel extends TreeModel {

    /** Returns the number of columns. */
    int getColumnCount();

    /** Returns the name of the given column. */
    String getColumnName(int column);

    /** Returns the class for the given column. */
    Class<?> getColumnClass(int column);

    /** Returns the value for the node at the given column. */
    Object getValueAt(Object node, int column);

    /** Returns true if the cell is editable. */
    default boolean isCellEditable(Object node, int column) {
        return false;
    }

    /** Sets the value for the node at the given column. */
    default void setValueAt(Object aValue, Object node, int column) {
        // not editable by default
    }
}