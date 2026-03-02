package capa.ghidra;

import javax.swing.tree.DefaultMutableTreeNode;
import java.util.List;

/**
 * Builds the JTreeTable model from CapaResults.
 *
 * Tree shape:
 *   [INFO] Program: foo.exe | Functions: 42 | OS: windows | Arch: x86
 *   [CAPABILITY] encrypt data using RC4              namespace: data-manipulation/...
 *     [MATCH] function (FUN_00401234)  0x00401234
 *       [STMT] and
 *         [FEAT] api: kernel32.CreateProcess         0x00401250
 *         [STMT] or
 *           [FEAT] number: 0x40 = PAGE_EXECUTE_RW    0x00401260
 */
public class CapaTreeModel extends AbstractTreeTableModel {

    private static final String[]   COL_NAMES  = { "Rule Information", "Address", "Details" };
    private static final Class<?>[] COL_TYPES  = { TreeTableModel.class, String.class, String.class };

    public CapaTreeModel() {
        super(placeholder());
    }

    public CapaTreeModel(CapaResults results, String filter) {
        super(buildTree(results, filter));
    }

    // -------------------------------------------------------------------------
    // Tree construction
    // -------------------------------------------------------------------------

    private static DefaultMutableTreeNode placeholder() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(
            new CapaNodeData(CapaNodeData.NodeType.ROOT, "Capa Results", "", ""));
        root.add(new DefaultMutableTreeNode(
            CapaNodeData.info("Open a binary and run Tools → Capa → Run Analysis")));
        return root;
    }

    public static DefaultMutableTreeNode buildTree(CapaResults results, String filter) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(
            new CapaNodeData(CapaNodeData.NodeType.ROOT, "Capa Results", "", ""));

        if (results == null) {
            root.add(new DefaultMutableTreeNode(CapaNodeData.info("No results available")));
            return root;
        }

        root.add(new DefaultMutableTreeNode(CapaNodeData.info(String.format(
            "Program: %s  |  Functions: %d  |  OS: %s  |  Arch: %s",
            nvl(results.programName), results.functionCount,
            nvl(results.os), nvl(results.arch)))));

        if (results.rules == null || results.rules.isEmpty()) {
            root.add(new DefaultMutableTreeNode(CapaNodeData.info("No capabilities detected")));
            return root;
        }

        String fl = filter == null ? "" : filter.trim().toLowerCase();

        for (CapaResults.Rule rule : results.rules.values()) {
            if (rule.meta == null) continue;

            if (!fl.isEmpty()) {
                boolean nm = rule.meta.name      != null && rule.meta.name.toLowerCase().contains(fl);
                boolean ns = rule.meta.namespace != null && rule.meta.namespace.toLowerCase().contains(fl);
                if (!nm && !ns) continue;
            }

            int matchCount = rule.matches == null ? 0 : rule.matches.size();
            String capLabel = matchCount > 1
                ? rule.meta.name + " (" + matchCount + " matches)"
                : rule.meta.name;

            DefaultMutableTreeNode capNode = new DefaultMutableTreeNode(
                CapaNodeData.capability(capLabel, rule.meta.namespace));

            if (rule.matches != null) {
                for (CapaResults.MatchEntry me : rule.matches) {
                    capNode.add(buildMatchNode(me.address, me.match, rule.meta.scope));
                }
            }

            root.add(capNode);
        }

        return root;
    }

    private static DefaultMutableTreeNode buildMatchNode(
            String scopeAddress, CapaResults.Match match, String scope) {

        if (match == null) {
            return new DefaultMutableTreeNode(CapaNodeData.info("(empty match)"));
        }

        CapaResults.MatchNode node = match.node;

        // Feature node (leaf)
        if (node != null && "feature".equals(node.nodeType)) {
            String addr = bestAddress(match.locations, scopeAddress);
            DefaultMutableTreeNode treeNode = new DefaultMutableTreeNode(
                new CapaNodeData(CapaNodeData.NodeType.MATCH, node.label(), addr, ""));
            for (String capture : match.captures.keySet()) {
                String capAddr = bestAddress(match.captures.get(capture), addr);
                treeNode.add(new DefaultMutableTreeNode(new CapaNodeData(
                    CapaNodeData.NodeType.MATCH, "match: " + capture, capAddr, "")));
            }
            return treeNode;
        }

        // Statement node (and / or / not / optional / some)
        if (node != null && "statement".equals(node.nodeType)) {
            String addr  = bestAddress(match.locations, scopeAddress);
            String label;
            if ("function".equals(scope) && match.children != null && !match.children.isEmpty()
                    && isTopLevelScope(match)) {
                label = "function (" + functionName(addr) + ")";
            } else if ("basic block".equals(node.statementType)) {
                label = "basic block @ " + addr;
            } else {
                label = node.label();
            }

            DefaultMutableTreeNode treeNode = new DefaultMutableTreeNode(
                new CapaNodeData(CapaNodeData.NodeType.MATCH, label, addr, ""));
            if (match.children != null) {
                for (CapaResults.Match child : match.children) {
                    treeNode.add(buildMatchNode(addr, child, scope));
                }
            }
            return treeNode;
        }

        // Fallback
        String addr = bestAddress(match.locations, scopeAddress);
        DefaultMutableTreeNode fallback = new DefaultMutableTreeNode(
            new CapaNodeData(CapaNodeData.NodeType.MATCH, "(match)", addr, ""));
        if (match.children != null) {
            for (CapaResults.Match child : match.children) {
                fallback.add(buildMatchNode(addr, child, scope));
            }
        }
        return fallback;
    }

    // -------------------------------------------------------------------------
    // TreeTableModel
    // -------------------------------------------------------------------------

    @Override public int      getColumnCount()             { return COL_NAMES.length; }
    @Override public String   getColumnName(int col)       { return COL_NAMES[col]; }
    @Override public Class<?> getColumnClass(int col)      { return COL_TYPES[col]; }

    @Override
    public Object getValueAt(Object node, int column) {
        if (!(node instanceof DefaultMutableTreeNode)) return null;
        Object userObj = ((DefaultMutableTreeNode) node).getUserObject();
        if (!(userObj instanceof CapaNodeData)) return null;
        CapaNodeData d = (CapaNodeData) userObj;
        switch (column) {
            case 0:  return d;
            case 1:  return d.getAddress();
            case 2:  return d.getDetails();
            default: return null;
        }
    }

    @Override public Object  getChild(Object parent, int index) { return ((DefaultMutableTreeNode) parent).getChildAt(index); }
    @Override public int     getChildCount(Object parent)       { return ((DefaultMutableTreeNode) parent).getChildCount(); }
    @Override public boolean isLeaf(Object node)                { return ((DefaultMutableTreeNode) node).isLeaf(); }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static boolean isTopLevelScope(CapaResults.Match match) {
        // A top-level function scope match has an "and" statement as its root node
        return match.node != null && "statement".equals(match.node.nodeType);
    }

    private static String bestAddress(List<String> locations, String fallback) {
        return (locations != null && !locations.isEmpty()) ? locations.get(0) : nvl(fallback);
    }

    private static String functionName(String addr) {
        if (addr == null || addr.isEmpty()) return "?";
        return "FUN_" + addr.replace("0x", "").replace("0X", "").toUpperCase();
    }

    private static String nvl(String s) { return s != null ? s : ""; }
}