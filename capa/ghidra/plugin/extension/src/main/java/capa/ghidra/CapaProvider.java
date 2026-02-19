package capa.ghidra;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.awt.*;

public class CapaProvider extends ComponentProvider {

    private final JTextArea outputArea;
    private final JLabel statusLabel;

    public CapaProvider(PluginTool tool, String owner) {
        super(tool, "Capa Explorer", owner);
        
        // Create UI components
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        statusLabel = new JLabel("Ready");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(outputArea), BorderLayout.CENTER);
        panel.add(statusLabel, BorderLayout.SOUTH);
        return panel;
    }

    /**
     * Show loading message.
     */
    public void showLoading(String message) {
        statusLabel.setText("⏳ " + message);
        outputArea.setText("Loading...\n\n" + message);
    }
    
    /**
     * Show error message.
     */
    public void showError(String errorMessage) {
        statusLabel.setText("Error");
        outputArea.setText("ERROR: " + errorMessage);
    }
    
    /**
     * Display analysis results.
     */
    public void displayResults(CapaResults results) {
        statusLabel.setText("Analysis Complete");
        
        StringBuilder output = new StringBuilder();
        output.append("=== Capa Analysis Results ===\n\n");
        
        // Program info
        output.append("Program: ").append(results.programName != null ? results.programName : "Unknown").append("\n");
        output.append("Path: ").append(results.programPath != null ? results.programPath : "Unknown").append("\n");
        output.append("Architecture: ").append(results.language != null ? results.language : "Unknown").append("\n");
        output.append("Compiler: ").append(results.compiler != null ? results.compiler : "Unknown").append("\n");
        output.append("\n");
        
        // Function counts
        output.append("Functions: ").append(results.functionCount).append("\n");
        output.append("External Functions: ").append(results.externalFunctionCount).append("\n");
        output.append("\n");
        
        // Memory blocks
        if (results.memoryBlocks != null && !results.memoryBlocks.isEmpty()) {
            output.append("=== Memory Blocks (").append(results.memoryBlocks.size()).append(") ===\n");
            for (CapaResults.MemoryBlock block : results.memoryBlocks) {
                output.append("  ").append(block.name).append(": ");
                output.append(block.start).append(" - ").append(block.end);
                output.append(" (").append(block.size).append(" bytes)\n");
            }
            output.append("\n");
        }
        
        // Capabilities
        if (results.capabilities != null && !results.capabilities.isEmpty()) {
            output.append("=== Detected Capabilities (").append(results.capabilities.size()).append(") ===\n");
            for (CapaResults.Capability cap : results.capabilities) {
                output.append("\n  ").append(cap.name).append("\n");
                output.append("    Namespace: ").append(cap.namespace != null ? cap.namespace : "unknown").append("\n");
                if (cap.description != null) {
                    output.append("    Description: ").append(cap.description).append("\n");
                }
                if (cap.matches != null && !cap.matches.isEmpty()) {
                    output.append("    Matches: ").append(cap.matches.size()).append("\n");
                }
            }
        } else {
            output.append("=== Capabilities ===\n");
            output.append("(Capa framework integration pending)\n");
        }
        
        output.append("\n");
        output.append("Analysis complete.\n");
        
        outputArea.setText(output.toString());
        outputArea.setCaretPosition(0); // Scroll to top
    }

    /**
     * Clear the output area.
     */
    public void clear() {
        outputArea.setText("");
        statusLabel.setText("Ready");
    }

    /**
     * Handle program change events.
     */
    public void onProgramChanged(Program program) {
        clear();
        if (program != null) {
            outputArea.setText("Program loaded: " + program.getName() + "\n\nRun analysis from Tools → Capa → Run Analysis");
            statusLabel.setText("Ready");
        }
    }
}