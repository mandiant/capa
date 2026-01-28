package capa.ghidra;

import java.io.PrintWriter;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

import generic.jar.ResourceFile;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScript;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.program.model.listing.Program;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Capa",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Run capa analysis",
    description = "Capa explorer MVP for Ghidra"
)
public class CapaPlugin extends ProgramPlugin {

    public CapaPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    private void createActions() {
        DockingAction action = new DockingAction("Run capa analysis", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                runCapaAnalysis();
            }
        };

        action.setMenuBarData(
            new MenuData(new String[] { "Tools", "Run capa analysis" })
        );

        tool.addAction(action);
    }

    private void runCapaAnalysis() {
        Program program = currentProgram;

        if (program == null) {
            Msg.showInfo(this, null, "Capa", "No program is currently open.");
            return;
        }

        CapaAnalysisTask task = new CapaAnalysisTask(program);
        TaskLauncher.launch(task);
    }

    /**
     * Background task that executes the capa Python script using PyGhidra.
     * This ensures the already-analyzed Program object is passed to Python
     * without reanalysis or subprocess execution.
     */
    private class CapaAnalysisTask extends Task {
        private final Program program;

        public CapaAnalysisTask(Program program) {
            super("Running capa analysis", true, false, true);
            this.program = program;
        }

        @Override
        public void run(TaskMonitor monitor) {
            try {
                monitor.setMessage("Finding capa script...");

                ResourceFile scriptFile = GhidraScriptUtil.findScriptByName("RunCapaMVP.py");

                if (scriptFile == null) {
                    Msg.showError(this, null, "Capa Error", 
                        "RunCapaMVP.py not found in script paths.");
                    return;
                }

                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
                
                if (provider == null) {
                    Msg.showError(this, null, "Capa Error", 
                        "No script provider found for Python scripts.");
                    return;
                }

                monitor.setMessage("Creating script instance...");

                PrintWriter writer = new PrintWriter(System.out, true);
                GhidraScript script = provider.getScriptInstance(scriptFile, writer);

                if (script == null) {
                    Msg.showError(this, null, "Capa Error", 
                        "Could not create script instance.");
                    return;
                }

                monitor.setMessage("Preparing analysis state...");

                GhidraState state = new GhidraState(
                    tool,
                    tool.getProject(),
                    program,
                    null,
                    null,
                    null
                );

                monitor.setMessage("Executing capa analysis via PyGhidra...");

                // Execute script with PyGhidra - passes Program object directly
                // Note: execute() is deprecated in Ghidra 12.0+, but remains the 
                // cleanest way to pass GhidraState to Python for this MVP.
                // Future iterations can migrate to the newer API.
                boolean success = executeScript(script, state, monitor, writer);

                if (success) {
                    Msg.showInfo(this, null, "Capa", 
                        "Analysis complete. Check Ghidra console for results.");
                }

            } catch (Exception e) {
                Msg.showError(this, null, "Capa Execution Failed", 
                    "Error running capa analysis: " + e.getMessage(), e);
                e.printStackTrace();
            }
        }

        /**
         * Execute the script via PyGhidra with the Program object.
         * Uses deprecated execute() method for MVP - will be updated in future versions.
         */
        @SuppressWarnings("deprecation")
        private boolean executeScript(GhidraScript script, GhidraState state, 
                                     TaskMonitor monitor, PrintWriter writer) {
            try {
                script.execute(state, monitor, writer);
                return true;
            } catch (Exception e) {
                Msg.showError(this, null, "Capa Execution Failed", 
                    "Script execution error: " + e.getMessage(), e);
                return false;
            }
        }
    }
}