package capa.ghidra;

import com.google.gson.*;
import docking.ComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

/**
 * CapaProvider — the main Ghidra component window for the capa extension.
 *
 * UI mirrors the IDA FLARE capa explorer:
 *   ┌──────────────────────────────────────────────────────┐
 *   │ [✓] Limit results to current function   [✓] Show matches by function │
 *   │ search...                                            │
 *   ├──────────────────────────────────────────────────────┤
 *   │ Rule Information          │ Address │ Details        │
 *   │  ▶ create HTTP request…   │         │ comm/http/…    │
 *   │    ▼ function(sub_401880) │ 00401880│                │
 *   │        and                │         │                │
 *   │          api(shell32.…)   │ 00401981│ call ds:…      │
 *   ├──────────────────────────────────────────────────────┤
 *   │ [Analyze] [Reset] [Settings]                [Save]  │
 *   │ capa rules directory: /path/to/rules (N rules)      │
 *   └──────────────────────────────────────────────────────┘
 */
public class CapaProvider extends ComponentProvider {

    // ------------------------------------------------------------------ //
    //  State                                                               //
    // ------------------------------------------------------------------ //

    private final CapaPlugin plugin;
    private Program currentProgram;

    // UI references
    private JPanel     mainPanel;
    private JCheckBox  limitToFunctionCheckbox;
    private JCheckBox  showByFunctionCheckbox;
    private JTextField searchField;
    private JTreeTable treeTable;
    private CapaResultsTreeModel treeTableModel;
    private JScrollPane scrollPane;

    private JButton analyzeButton;
    private JButton resetButton;
    private JButton settingsButton;

    private JLabel statusLabel;
    private JLabel rulesPathLabel;

    // ------------------------------------------------------------------ //
    //  Constructor                                                         //
    // ------------------------------------------------------------------ //

    public CapaProvider(PluginTool tool, String owner, CapaPlugin plugin) {
        super(tool, "Capa Explorer", owner);
        this.plugin = plugin;
        buildUI();
        setVisible(true);
    }

    // ------------------------------------------------------------------ //
    //  ComponentProvider API                                               //
    // ------------------------------------------------------------------ //

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    // ------------------------------------------------------------------ //
    //  UI construction                                                     //
    // ------------------------------------------------------------------ //

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout(0, 0));
        mainPanel.setPreferredSize(new Dimension(860, 500));

        mainPanel.add(buildTopPanel(),    BorderLayout.NORTH);
        mainPanel.add(buildTreePanel(),   BorderLayout.CENTER);
        mainPanel.add(buildBottomPanel(), BorderLayout.SOUTH);
    }

    /** Checkboxes + search bar */
    private JPanel buildTopPanel() {
        JPanel top = new JPanel(new BorderLayout(4, 2));
        top.setBorder(BorderFactory.createEmptyBorder(4, 6, 2, 6));

        // Checkbox row
        JPanel checkboxRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        limitToFunctionCheckbox = new JCheckBox("Limit results to current function");
        showByFunctionCheckbox  = new JCheckBox("Show matches by function");
        limitToFunctionCheckbox.setFocusable(false);
        showByFunctionCheckbox.setFocusable(false);

        limitToFunctionCheckbox.addActionListener(e -> refreshFilter());
        showByFunctionCheckbox.addActionListener(e -> refreshFilter());

        checkboxRow.add(limitToFunctionCheckbox);
        checkboxRow.add(showByFunctionCheckbox);

        // Search row
        searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", "search...");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { refreshFilter(); }
            @Override public void removeUpdate(DocumentEvent e)  { refreshFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { refreshFilter(); }
        });

        top.add(checkboxRow,  BorderLayout.NORTH);
        top.add(searchField,  BorderLayout.CENTER);
        return top;
    }

    /** The JTreeTable in a scroll pane */
    private JScrollPane buildTreePanel() {
        treeTableModel = new CapaResultsTreeModel();
        treeTable      = new JTreeTable(treeTableModel);

        treeTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        treeTable.getColumnModel().getColumn(0).setPreferredWidth(380);
        treeTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        treeTable.getColumnModel().getColumn(2).setPreferredWidth(300);

        // Double-click navigates to address
        treeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    navigateToSelected();
                }
            }
        });

        scrollPane = new JScrollPane(treeTable);
        return scrollPane;
    }

    /** Analyze / Reset / Settings buttons + status labels */
    private JPanel buildBottomPanel() {
        JPanel bottom = new JPanel(new BorderLayout(0, 2));
        bottom.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        // Button row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

        analyzeButton  = new JButton("Analyze");
        resetButton    = new JButton("Reset");
        settingsButton = new JButton("Settings");

        analyzeButton.addActionListener(e  -> onAnalyze());
        resetButton.addActionListener(e    -> onReset());
        settingsButton.addActionListener(e -> onSettings());

        buttonRow.add(analyzeButton);
        buttonRow.add(resetButton);
        buttonRow.add(settingsButton);

        // Status row
        statusLabel    = new JLabel(" ");
        rulesPathLabel = new JLabel(" ");
        rulesPathLabel.setFont(rulesPathLabel.getFont().deriveFont(Font.PLAIN, 11f));
        rulesPathLabel.setForeground(Color.GRAY);

        updateRulesPathLabel();

        JPanel statusRow = new JPanel(new GridLayout(2, 1, 0, 0));
        statusRow.add(statusLabel);
        statusRow.add(rulesPathLabel);

        bottom.add(buttonRow,  BorderLayout.NORTH);
        bottom.add(statusRow,  BorderLayout.SOUTH);
        return bottom;
    }

    // ------------------------------------------------------------------ //
    //  Button handlers                                                     //
    // ------------------------------------------------------------------ //

    private void onAnalyze() {
        if (currentProgram == null) {
            Msg.showInfo(this, mainPanel, "Capa Analysis", "No program is currently open.");
            return;
        }
        plugin.runAnalysis(false);
    }

    private void onReset() {
        clearResults();
        setStatus("Results cleared.");
    }

    private void onSettings() {
        GhidraFileChooser chooser = new GhidraFileChooser(mainPanel);
        chooser.setTitle("Select capa rules directory");
        chooser.setApproveButtonText("Select");
        chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);

        // Pre-select existing path if any
        String existing = CapaCacheManager.readRulesDirectory();
        if (existing != null && !existing.isEmpty()) {
            chooser.setCurrentDirectory(new File(existing));
        }

        File selected = chooser.getSelectedFile();
        chooser.dispose();

        if (selected != null) {
            CapaCacheManager.writeRulesDirectory(selected.getAbsolutePath());
            updateRulesPathLabel();
            setStatus("Rules directory updated.");
        }
    }

    // ------------------------------------------------------------------ //
    //  Public display API (called from CapaPlugin / analysis task)        //
    // ------------------------------------------------------------------ //

    public void showLoading(String message) {
        SwingUtilities.invokeLater(() -> {
            setStatus(message);
            analyzeButton.setEnabled(false);
        });
    }

    public void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            setStatus("Error: " + message);
            analyzeButton.setEnabled(true);
        });
    }

    public void displayResults(String capaJson) {
        SwingUtilities.invokeLater(() -> {
            try {
                JsonObject json = JsonParser.parseString(capaJson).getAsJsonObject();
                treeTableModel = CapaResultsTreeModel.fromJson(json);
                treeTable.setModel(new TreeTableModelAdapter(treeTableModel, treeTable.getTree()));
                treeTable.getTree().setModel(treeTableModel);

                // Column widths after model swap
                treeTable.getColumnModel().getColumn(0).setPreferredWidth(380);
                treeTable.getColumnModel().getColumn(1).setPreferredWidth(110);
                treeTable.getColumnModel().getColumn(2).setPreferredWidth(300);

                // Count top-level rules
                int ruleCount = treeTableModel.getChildCount(treeTableModel.getRoot());
                // Subtract 1 if root itself is the "capa results" invisible root
                setStatus("Analysis complete — " + ruleCount + " rule(s) matched.");
            } catch (Exception e) {
                showError("Failed to parse results: " + e.getMessage());
                Msg.error(this, "JSON parse error", e);
            }
            analyzeButton.setEnabled(true);
        });
    }

    public void clearResults() {
        SwingUtilities.invokeLater(() -> {
            treeTableModel = new CapaResultsTreeModel();
            treeTable.setModel(new TreeTableModelAdapter(treeTableModel, treeTable.getTree()));
            treeTable.getTree().setModel(treeTableModel);
            analyzeButton.setEnabled(true);
        });
    }

    // ------------------------------------------------------------------ //
    //  Program tracking                                                    //
    // ------------------------------------------------------------------ //

    public void onProgramActivated(Program program) {
        this.currentProgram = program;
        clearResults();
        setStatus(program != null ? "Ready — click Analyze to run capa." : "No program open.");
    }

    public void onProgramDeactivated(Program program) {
        this.currentProgram = null;
        clearResults();
        setStatus("No program open.");
    }

    // ------------------------------------------------------------------ //
    //  Navigation (double-click on address cell)                          //
    // ------------------------------------------------------------------ //

    private void navigateToSelected() {
        int row = treeTable.getSelectedRow();
        if (row < 0) return;

        Object addressVal = treeTable.getValueAt(row, 1);
        if (!(addressVal instanceof String)) return;
        String addrStr = ((String) addressVal).trim();
        if (addrStr.isEmpty()) return;

        try {
            long offset = Long.parseUnsignedLong(
                    addrStr.startsWith("0x") || addrStr.startsWith("0X")
                            ? addrStr.substring(2) : addrStr, 16);

            GoToService goToService = dockingTool.getService(GoToService.class);
            if (goToService == null || currentProgram == null) return;

            Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(offset);
            goToService.goTo(addr);
        } catch (NumberFormatException ignored) {}
    }

    // ------------------------------------------------------------------ //
    //  Filter (search / checkboxes) — placeholder, expand as needed       //
    // ------------------------------------------------------------------ //

    private void refreshFilter() {
        // TODO: implement live filtering of tree rows based on searchField text
        // and the two checkboxes. For now just a no-op so the UI is wired.
    }

    // ------------------------------------------------------------------ //
    //  Helpers                                                             //
    // ------------------------------------------------------------------ //

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }

    private void updateRulesPathLabel() {
        String rulesDir = CapaCacheManager.readRulesDirectory();
        if (rulesDir == null || rulesDir.isEmpty()) {
            rulesPathLabel.setText("capa rules directory: (not configured — click Settings)");
        } else {
            // Count yml files in root to mimic "474 rules"
            File dir = new File(rulesDir);
            int ruleCount = countYmlFiles(dir);
            rulesPathLabel.setText("capa rules directory: " + rulesDir +
                    (ruleCount > 0 ? " (" + ruleCount + " rules)" : ""));
        }
    }

    private int countYmlFiles(File dir) {
        if (dir == null || !dir.isDirectory()) return 0;
        int count = 0;
        File[] files = dir.listFiles();
        if (files == null) return 0;
        for (File f : files) {
            if (f.isDirectory()) {
                count += countYmlFiles(f);
            } else if (f.getName().endsWith(".yml") || f.getName().endsWith(".yaml")) {
                count++;
            }
        }
        return count;
    }
}