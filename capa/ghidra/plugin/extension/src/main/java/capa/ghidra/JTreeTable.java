package capa.ghidra;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.MouseEvent;

/**
 * A JTable that renders its first column as a JTree, giving a
 * tree-table (hierarchical table) appearance.
 *
 * Adapted from the classic Sun/Oracle JTreeTable pattern, updated
 * for modern Java (no raw types, @Override annotations).
 */
public class JTreeTable extends JTable {

    final TreeTableCellRenderer tree;

    public JTreeTable(TreeTableModel treeTableModel) {
        super();

        // Create the tree renderer/editor
        tree = new TreeTableCellRenderer(treeTableModel);

        // Use the adapter as our table model
        super.setModel(new TreeTableModelAdapter(treeTableModel, tree));

        // Sync tree and table selection
        tree.setSelectionModel(new DefaultTreeSelectionModel() {
            {
                setSelectionModel(listSelectionModel);
            }
        });

        // Row heights must match
        tree.setRowHeight(getRowHeight());

        // Register tree as renderer and editor for the tree column
        setDefaultRenderer(TreeTableModel.class, tree);
        setDefaultEditor(TreeTableModel.class, new TreeTableCellEditor());

        // Visual tweaks
        setShowGrid(false);
        setIntercellSpacing(new Dimension(0, 0));

        // Left-align header
        DefaultTableCellRenderer headerRenderer = new DefaultTableCellRenderer();
        headerRenderer.setHorizontalAlignment(SwingConstants.LEFT);
        getTableHeader().setDefaultRenderer(headerRenderer);
    }

    /**
     * Workaround: return -1 for the editing row when the tree column is being
     * edited so the table doesn't try to paint the cell itself.
     */
    @Override
    public int getEditingRow() {
        return (getColumnClass(editingColumn) == TreeTableModel.class) ? -1 : editingRow;
    }

    /**
     * Forward mouse events to the tree so expand/collapse works.
     */
    @Override
    protected void processMouseEvent(MouseEvent e) {
        super.processMouseEvent(e);
    }

    // -------------------------------------------------------------------------
    // Tree column renderer
    // -------------------------------------------------------------------------

    /**
     * Renders the tree column by painting the JTree at the correct row offset.
     */
    public class TreeTableCellRenderer extends JTree implements TableCellRenderer {

        private int visibleRow;

        public TreeTableCellRenderer(TreeModel model) {
            super(model);
        }

        /**
         * Keep the tree as tall as the whole table so all rows paint correctly.
         */
        @Override
        public void setBounds(int x, int y, int w, int h) {
            super.setBounds(x, 0, w, JTreeTable.this.getHeight());
        }

        /**
         * Translate painting so only the correct row is visible.
         */
        @Override
        public void paint(Graphics g) {
            g.translate(0, -visibleRow * getRowHeight());
            super.paint(g);
        }

        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value,
                boolean isSelected, boolean hasFocus,
                int row, int column) {
            setBackground(isSelected
                ? table.getSelectionBackground()
                : table.getBackground());
            visibleRow = row;
            return this;
        }
    }

    // -------------------------------------------------------------------------
    // Tree column editor (needed to receive click events for expand/collapse)
    // -------------------------------------------------------------------------

    public class TreeTableCellEditor extends AbstractCellEditor implements TableCellEditor {

        @Override
        public Component getTableCellEditorComponent(
                JTable table, Object value,
                boolean isSelected, int row, int column) {
            return tree;
        }

        @Override
        public Object getCellEditorValue() {
            return null;
        }
    }
}