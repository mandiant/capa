package capa.ghidra;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JComponent;
import java.awt.Font;

public class CapaProvider extends ComponentProvider {

    private final JTextArea output;

    public CapaProvider(PluginTool tool) {
        super(tool, "Capa Explorer", "CapaExplorer");

        output = new JTextArea();
        output.setEditable(false);
        output.setFont(new Font("Monospaced", Font.PLAIN, 12));

        tool.addComponentProvider(this, true);
        tool.showComponentProvider(this, true);
    }

    @Override
    public JComponent getComponent() {
        return new JScrollPane(output);
    }

    public void showMessage(String message) {
        output.append(message + "\n");
    }

    public void clear() {
        output.setText("");
    }

    public void onProgramChanged(Program program) {
        clear();

        if (program != null) {
            showMessage("Program loaded: " + program.getName());
        }
    }
}