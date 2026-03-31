package capa.ghidra;

import javax.swing.event.EventListenerList;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

/**
 * Abstract base class for TreeTableModel implementations.
 * Handles listener management and event firing.
 */
public abstract class AbstractTreeTableModel implements TreeTableModel {

    protected Object root;
    protected EventListenerList listenerList = new EventListenerList();

    public AbstractTreeTableModel(Object root) {
        this.root = root;
    }

    // -------------------------------------------------------------------------
    // TreeModel
    // -------------------------------------------------------------------------

    @Override
    public Object getRoot() {
        return root;
    }

    @Override
    public boolean isLeaf(Object node) {
        return getChildCount(node) == 0;
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue) {
        // not used
    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        int count = getChildCount(parent);
        for (int i = 0; i < count; i++) {
            if (getChild(parent, i).equals(child)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public void addTreeModelListener(TreeModelListener l) {
        listenerList.add(TreeModelListener.class, l);
    }

    @Override
    public void removeTreeModelListener(TreeModelListener l) {
        listenerList.remove(TreeModelListener.class, l);
    }

    // -------------------------------------------------------------------------
    // TreeTableModel defaults
    // -------------------------------------------------------------------------

    @Override
    public boolean isCellEditable(Object node, int column) {
        // Only the tree column (0) is "editable" so the tree can receive events
        return getColumnClass(column) == TreeTableModel.class;
    }

    @Override
    public void setValueAt(Object aValue, Object node, int column) {
        // not editable
    }

    // -------------------------------------------------------------------------
    // Event helpers
    // -------------------------------------------------------------------------

    protected void fireTreeStructureChanged(Object source, Object[] path,
            int[] childIndices, Object[] children) {
        TreeModelEvent event = new TreeModelEvent(source, path, childIndices, children);
        for (TreeModelListener l : listenerList.getListeners(TreeModelListener.class)) {
            l.treeStructureChanged(event);
        }
    }

    protected void fireTreeNodesChanged(Object source, Object[] path,
            int[] childIndices, Object[] children) {
        TreeModelEvent event = new TreeModelEvent(source, path, childIndices, children);
        for (TreeModelListener l : listenerList.getListeners(TreeModelListener.class)) {
            l.treeNodesChanged(event);
        }
    }
}