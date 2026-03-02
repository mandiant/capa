package capa.ghidra;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GhidraScriptService;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import ghidra.util.task.TaskMonitor;

/**
 * CapaPlugin
 *
 * Key fix: runScript() is asynchronous. We use a lock + TaskListener
 * to wait for the script to fully finish before reading the cache.
 * Previously we read the cache immediately after runScript() returned,
 * which was before the Python script had written anything.
 */
@PluginInfo(
    status           = PluginStatus.STABLE,
    packageName      = "Capa",
    category         = PluginCategoryNames.ANALYSIS,
    shortDescription = "Run capa analysis",
    description      = "Integrates Mandiant capa capability detection with Ghidra"
)
public class CapaPlugin extends ProgramPlugin {

    private static final String SCRIPT_NAME = "RunCapaMVP.py";
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
            public void actionPerformed(ActionContext context) { runCapaAnalysis(false); }
        };
        runAction.setMenuBarData(new MenuData(new String[]{"Tools", "Capa", "Run Analysis"}));
        runAction.setDescription("Run capa capability analysis on the current program");
        tool.addAction(runAction);

        DockingAction forceAction = new DockingAction("Force Re-run capa analysis", getName()) {
            @Override
            public void actionPerformed(ActionContext context) { runCapaAnalysis(true); }
        };
        forceAction.setMenuBarData(new MenuData(new String[]{"Tools", "Capa", "Force Re-run Analysis"}));
        forceAction.setDescription("Force re-run capa analysis (ignore cached results)");
        tool.addAction(forceAction);
    }

    private void runCapaAnalysis(boolean forceRerun) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showInfo(this, null, "Capa Analysis", "No program is currently open.");
            return;
        }

        tool.showComponentProvider(provider, true);

        if (!forceRerun && CapaCacheManager.cacheExists(program)) {
            int choice = OptionDialog.showYesNoCancelDialog(null, "Capa Analysis",
                "Cached results exist for this program.\n\n" +
                "• Yes    = Load cached results\n• No     = Re-run analysis\n• Cancel = Abort");
            if (choice == OptionDialog.YES_OPTION)  { loadCachedResults(program); return; }
            if (choice == OptionDialog.CANCEL_OPTION) return;
        }

        TaskLauncher.launch(new CapaAnalysisTask(program, forceRerun));
    }

    private void loadCachedResults(Program program) {
        provider.showLoading("Loading cached results...");
        String json = CapaCacheManager.readCache(program);
        if (json == null) { provider.showError("Could not read cached results."); return; }
        try {
            provider.displayResults(CapaResults.fromJson(json), program);
        } catch (Exception e) {
            provider.showError("Failed to parse cached results: " + e.getMessage());
            Msg.showError(this, null, "Cache Parse Error", "Could not parse cached results.", e);
        }
    }

    private class CapaAnalysisTask extends Task {

        private final Program program;
        private final boolean forceRerun;

        CapaAnalysisTask(Program program, boolean forceRerun) {
            super("Running capa analysis", true, false, true);
            this.program    = program;
            this.forceRerun = forceRerun;
        }

        @Override
        public void run(TaskMonitor monitor) {
            try {
                SwingUtilities.invokeLater(() -> provider.showLoading("Running capa analysis..."));

                if (forceRerun) {
                    monitor.setMessage("Clearing cached results...");
                    CapaCacheManager.deleteCache(program);
                }

                GhidraScriptService scriptService = tool.getService(GhidraScriptService.class);
                if (scriptService == null) {
                    showErrorInUI("GhidraScriptService not available. Ensure PyGhidra is enabled.");
                    return;
                }

                monitor.setMessage("Executing capa analysis script...");

                // runScript() is async — use a lock to wait for completion
                final boolean[] done      = { false };
                final boolean[] cancelled = { false };
                final Object    lock      = new Object();

                scriptService.runScript(SCRIPT_NAME, new TaskListener() {
                    @Override
                    public void taskCompleted(Task t) {
                        synchronized (lock) { done[0] = true; lock.notifyAll(); }
                    }
                    @Override
                    public void taskCancelled(Task t) {
                        synchronized (lock) { done[0] = true; cancelled[0] = true; lock.notifyAll(); }
                    }
                });

                // Wait for the script to finish before reading cache
                synchronized (lock) {
                    while (!done[0]) {
                        try { lock.wait(500); } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt(); break;
                        }
                        if (monitor.isCancelled()) return;
                    }
                }

                if (cancelled[0] || monitor.isCancelled()) return;

                // Script is done — now it is safe to read the cache
                monitor.setMessage("Reading analysis results...");
                String json = CapaCacheManager.readCache(program);
                if (json == null) {
                    showErrorInUI("Analysis produced no results. Check the Ghidra console.");
                    return;
                }

                CapaResults results = CapaResults.fromJson(json);
                SwingUtilities.invokeLater(() -> provider.displayResults(results, program));

            } catch (Exception e) {
                showErrorInUI("Unexpected error: " + e.getMessage());
                Msg.showError(this, null, "Capa Analysis Failed", "Unexpected error.", e);
            }
        }

        private void showErrorInUI(String msg) {
            SwingUtilities.invokeLater(() -> provider.showError(msg));
        }
    }
}