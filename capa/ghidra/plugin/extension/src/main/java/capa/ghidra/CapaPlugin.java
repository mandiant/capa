package capa.ghidra;

import java.io.PrintWriter;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GhidraScriptService;

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
    description = "Integrates Mandiant capa capability detection with Ghidra"
)
public class CapaPlugin extends ProgramPlugin {

    private CapaProvider provider;

    public CapaPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    @Override
    protected void init() {
        super.init();
        provider = new CapaProvider(tool, getName());
    }

    private void createActions() {

        DockingAction runAction = new DockingAction("Run capa analysis", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                runCapaAnalysis(false);
            }
        };

        runAction.setMenuBarData(new MenuData(new String[] { "Tools", "Capa", "Run Analysis" }));
        runAction.setDescription("Run capa capability analysis on the current program");
        tool.addAction(runAction);

        DockingAction forceRunAction = new DockingAction("Force Re-run capa analysis", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                runCapaAnalysis(true);
            }
        };

        forceRunAction.setMenuBarData(new MenuData(new String[] { "Tools", "Capa", "Force Re-run Analysis" }));
        forceRunAction.setDescription("Force re-run capa analysis (ignore cache)");
        tool.addAction(forceRunAction);
    }

    private void runCapaAnalysis(boolean forceRerun) {

        Program program = currentProgram;

        if (program == null) {
            Msg.showInfo(this, null, "Capa Analysis", "No program is currently open.");
            return;
        }

        tool.showComponentProvider(provider, true);

        boolean cacheExists = CapaCacheManager.cacheExists(program);

        if (!forceRerun && cacheExists) {
            int choice = askUserCachePreference();

            if (choice == 0) {
                loadCachedResults(program);
                return;
            } else if (choice == 1) {
                forceRerun = true;
            } else {
                return;
            }
        }

        CapaAnalysisTask task = new CapaAnalysisTask(program, forceRerun);
        TaskLauncher.launch(task);
    }

    private int askUserCachePreference() {

        int choice = docking.widgets.OptionDialog.showYesNoCancelDialog(
            null,
            "Capa Analysis",
            "Cached results found for this program.\n\n" +
            "Would you like to load the cached results or re-run the analysis?\n\n" +
            "• Yes = Load Cached Results\n" +
            "• No = Re-run Analysis\n" +
            "• Cancel = Abort"
        );

        if (choice == docking.widgets.OptionDialog.YES_OPTION) return 0;
        if (choice == docking.widgets.OptionDialog.NO_OPTION) return 1;
        return 2;
    }

    private void loadCachedResults(Program program) {

        provider.showLoading("Loading cached results...");
        String json = CapaCacheManager.readCache(program);

        if (json == null) {
            provider.showError("Failed to read cache file.");
            Msg.showError(this, null, "Cache Error", "Could not read cached results.");
            return;
        }

        try {
            CapaResults results = CapaResults.fromJson(json);
            provider.displayResults(results);
            Msg.showInfo(this, null, "Capa Analysis", "Loaded cached results from previous analysis.");
        }
        catch (Exception e) {
            provider.showError("Failed to parse cached results: " + e.getMessage());
            Msg.showError(this, null, "Cache Parse Error", "Could not parse cached results.", e);
        }
    }

    private class CapaAnalysisTask extends Task {

        private final Program program;
        private final boolean forceRerun;

        public CapaAnalysisTask(Program program, boolean forceRerun) {
            super("Running capa analysis", true, false, true);
            this.program = program;
            this.forceRerun = forceRerun;
        }

        @Override
        public void run(TaskMonitor monitor) {

            try {
                SwingUtilities.invokeLater(() -> provider.showLoading("Running capa analysis..."));

                if (forceRerun) {
                    monitor.setMessage("Clearing old cache...");
                    CapaCacheManager.deleteCache(program);
                }

                monitor.setMessage("Executing capa analysis via PyGhidra...");
                boolean success = executeScriptViaService();

                if (!success) {
                    showErrorInUI("Script execution failed. Check console for details.");
                    return;
                }

                monitor.setMessage("Waiting for analysis results...");
                String json = waitForCache(program, monitor);

                if (json == null) {
                    showErrorInUI("Analysis finished but cache was not produced (timeout).");
                    return;
                }

                CapaResults results = CapaResults.fromJson(json);

                SwingUtilities.invokeLater(() -> provider.displayResults(results));

                Msg.showInfo(this, null, "Capa Analysis",
                        "Analysis complete. Results displayed in Capa Explorer window.");

            }
            catch (Exception e) {
                showErrorInUI("Unexpected error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        private boolean executeScriptViaService() {
            try {
                GhidraScriptService scriptService = tool.getService(GhidraScriptService.class);

                if (scriptService == null) {
                    Msg.showError(this, null, "Script Service Error",
                            "GhidraScriptService not available.");
                    return false;
                }

                String scriptName = "RunCapaMVP.py";
                scriptService.runScript(scriptName, null);
                return true;

            } catch (Exception e) {
                Msg.showError(this, null, "Script Execution Error",
                        "Failed to execute capa script: " + e.getMessage(), e);
                return false;
            }
        }

        /**
         * NEW METHOD — waits until Python writes cache
         */
        private String waitForCache(Program program, TaskMonitor monitor) {

            final int MAX_WAIT_MS = 30000;
            final int POLL_INTERVAL_MS = 500;

            long start = System.currentTimeMillis();

            while (!monitor.isCancelled()) {

                String json = CapaCacheManager.readCache(program);
                if (json != null) {
                    return json;
                }

                if (System.currentTimeMillis() - start > MAX_WAIT_MS) {
                    return null;
                }

                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }

            return null;
        }

        private void showErrorInUI(String errorMessage) {
            SwingUtilities.invokeLater(() -> provider.showError(errorMessage));
            Msg.showError(this, null, "Capa Analysis Failed", errorMessage);
        }
    }
}