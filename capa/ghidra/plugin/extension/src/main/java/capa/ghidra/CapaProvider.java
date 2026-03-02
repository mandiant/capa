package capa.ghidra;

import docking.ComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class CapaProvider extends ComponentProvider {

    private CapaResults currentResults;
    private Program     currentProgram;

    private JPanel     mainPanel;
    private JTextField searchField;
    private JTreeTable treeTable;
    private JLabel     statusLabel;

    public CapaProvider(PluginTool tool, String owner) {
        super(tool, "Capa Explorer", owner);
        buildUI();
        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout(4, 0));
        topPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        topPanel.add(new JLabel("Filter: "), BorderLayout.WEST);

        searchField = new JTextField();
        searchField.setToolTipText("Filter capabilities by name or namespace");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e)  { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        topPanel.add(searchField, BorderLayout.CENTER);

        treeTable = new JTreeTable(new CapaTreeModel());
        treeTable.setRowHeight(20);
        treeTable.getColumnModel().getColumn(0).setPreferredWidth(350);
        treeTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        treeTable.getColumnModel().getColumn(2).setPreferredWidth(200);

        treeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) navigateToSelectedRow();
            }
        });

        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));

        mainPanel.add(topPanel,             BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(treeTable), BorderLayout.CENTER);
        mainPanel.add(statusLabel,          BorderLayout.SOUTH);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public void showLoading(String message) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(message);
            rebuildTable(null, "");
        });
    }

    public void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Error");
            CapaTreeModel model = new CapaTreeModel();
            DefaultMutableTreeNode errorRoot = CapaTreeModel.buildTree(null, "");
            errorRoot.add(new DefaultMutableTreeNode(CapaNodeData.error(message)));
            treeTable.tree.setModel(model);
            treeTable.setModel(new TreeTableModelAdapter(model, treeTable.tree));
        });
    }

    public void displayResults(CapaResults results, Program program) {
        this.currentResults = results;
        this.currentProgram = program;
        SwingUtilities.invokeLater(() -> {
            searchField.setText("");
            rebuildTable(results, "");
            int capCount = (results != null && results.rules != null)
                ? results.rules.size() : 0;
            statusLabel.setText(String.format("Analysis complete — %d capabilities detected", capCount));
        });
    }

    public void onProgramChanged(Program program) {
        this.currentProgram = program;
        this.currentResults = null;
        SwingUtilities.invokeLater(() -> {
            rebuildTable(null, "");
            statusLabel.setText(program != null
                ? "Program loaded: " + program.getName() + " — run Tools → Capa → Run Analysis"
                : "Ready");
        });
    }

    // -------------------------------------------------------------------------
    // Table rebuilding
    // -------------------------------------------------------------------------

    private void rebuildTable(CapaResults results, String filter) {
        CapaTreeModel model = new CapaTreeModel(results, filter);
        treeTable.tree.setModel(model);
        treeTable.setModel(new TreeTableModelAdapter(model, treeTable.tree));

        if (treeTable.getColumnCount() >= 3) {
            treeTable.getColumnModel().getColumn(0).setPreferredWidth(350);
            treeTable.getColumnModel().getColumn(1).setPreferredWidth(120);
            treeTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        }

        for (int i = 0; i < treeTable.tree.getRowCount(); i++) {
            treeTable.tree.expandRow(i);
        }

        treeTable.revalidate();
        treeTable.repaint();
    }

    private void applyFilter() {
        rebuildTable(currentResults, searchField.getText());

        if (currentResults != null && currentResults.rules != null) {
            String filter = searchField.getText().trim().toLowerCase();
            long shown = currentResults.rules.values().stream()
                .filter(r -> filter.isEmpty()
                    || (r.meta.name      != null && r.meta.name.toLowerCase().contains(filter))
                    || (r.meta.namespace != null && r.meta.namespace.toLowerCase().contains(filter)))
                .count();
            statusLabel.setText(filter.isEmpty()
                ? String.format("Analysis complete — %d capabilities detected", currentResults.rules.size())
                : String.format("Showing %d of %d capabilities", shown, currentResults.rules.size()));
        }
    }

    // -------------------------------------------------------------------------
    // Navigation
    // -------------------------------------------------------------------------

    private void navigateToSelectedRow() {
        int row = treeTable.getSelectedRow();
        if (row < 0) return;

        TreePath path = treeTable.tree.getPathForRow(row);
        if (path == null) return;

        Object last = path.getLastPathComponent();
        if (!(last instanceof DefaultMutableTreeNode)) return;

        Object userObj = ((DefaultMutableTreeNode) last).getUserObject();
        if (!(userObj instanceof CapaNodeData)) return;

        CapaNodeData data = (CapaNodeData) userObj;
        if (data.getNodeType() != CapaNodeData.NodeType.MATCH) return;

        String addressStr = data.getAddress();
        if (addressStr == null || addressStr.isEmpty()) return;

        if (currentProgram == null) {
            Msg.showWarn(this, null, "Capa Explorer", "No program is currently open.");
            return;
        }

        GoToService goToService = getTool().getService(GoToService.class);
        if (goToService == null) {
            Msg.showWarn(this, null, "Capa Explorer", "GoToService not available.");
            return;
        }

        try {
            Address addr = currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(addressStr);
            goToService.goTo(addr);
        } catch (Exception e) {
            Msg.showWarn(this, null, "Capa Explorer",
                "Could not navigate to address: " + addressStr);
        }
    }
}
