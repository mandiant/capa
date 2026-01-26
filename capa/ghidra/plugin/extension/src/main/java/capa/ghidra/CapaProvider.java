package capa.ghidra;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JComponent;
import java.awt.Font;

import java.io.PrintWriter;
import java.io.StringWriter;

public class CapaProvider extends ComponentProvider {

    private final PluginTool tool;
    private final JTextArea output;

    public CapaProvider(PluginTool tool) {
        super(tool, "Capa Explorer", "CapaExplorer");
        this.tool = tool;

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

    public void runCapa(Program program) {

        // Ensure panel is visible
        tool.showComponentProvider(this, true);

        if (program == null) {
            output.setText("No program is currently open.\n");
            return;
        }

        output.setText("Running capa...\n");

        try {
            String result = CapaPythonBridge.run(program);
            output.append(result);
        }
        catch (Exception e) {
            Msg.error(this, "Error running capa", e);

            output.append("\nERROR:\n");

            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);

            output.append(sw.toString());
        }
    }
}
