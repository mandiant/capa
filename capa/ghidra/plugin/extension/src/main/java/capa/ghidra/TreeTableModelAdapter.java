package capa.ghidra;

import javax.swing.JTree;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.tree.TreePath;

/**
 * Adapts a TreeTableModel to a TableModel so that JTreeTable can use
 * a standard JTable underneath while the first column renders as a JTree.
 */
public class TreeTableModelAdapter extends AbstractTableModel {

    private final JTree tree;
    private final TreeTableModel treeTableModel;

    public TreeTableModelAdapter(TreeTableModel treeTableModel, JTree tree) {
        this.tree = tree;
        this.treeTableModel = treeTableModel;

        // Repaint table when tree expands/collapses
        tree.addTreeExpansionListener(new TreeExpansionListener() {
            @Override
            public void treeExpanded(TreeExpansionEvent event) {
                fireTableDataChanged();
            }

            @Override
            public void treeCollapsed(TreeExpansionEvent event) {
                fireTableDataChanged();
            }
        });

        // Forward tree model changes to table
        treeTableModel.addTreeModelListener(new TreeModelListener() {
            @Override
            public void treeNodesChanged(TreeModelEvent e) {
                delayedFireTableDataChanged();
            }

            @Override
            public void treeNodesInserted(TreeModelEvent e) {
                delayedFireTableDataChanged();
            }

            @Override
            public void treeNodesRemoved(TreeModelEvent e) {
                delayedFireTableDataChanged();
            }

            @Override
            public void treeStructureChanged(TreeModelEvent e) {
                delayedFireTableDataChanged();
            }
        });
    }

    // -------------------------------------------------------------------------
    // TableModel
    // -------------------------------------------------------------------------

    @Override
    public int getColumnCount() {
        return treeTableModel.getColumnCount();
    }

    @Override
    public String getColumnName(int column) {
        return treeTableModel.getColumnName(column);
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return treeTableModel.getColumnClass(column);
    }

    @Override
    public int getRowCount() {
        return tree.getRowCount();
    }

    @Override
    public Object getValueAt(int row, int column) {
        return treeTableModel.getValueAt(nodeForRow(row), column);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return treeTableModel.isCellEditable(nodeForRow(row), column);
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        treeTableModel.setValueAt(value, nodeForRow(row), column);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Object nodeForRow(int row) {
        TreePath treePath = tree.getPathForRow(row);
        return treePath == null ? null : treePath.getLastPathComponent();
    }

    private void delayedFireTableDataChanged() {
        javax.swing.SwingUtilities.invokeLater(this::fireTableDataChanged);
    }
}