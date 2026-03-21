package capa.ghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScriptUtil;
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
import generic.jar.ResourceFile;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Capa",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "capa capability detection",
    description = "Integrates Mandiant capa malware capability detection with Ghidra. " +
                  "All actions are performed from the Capa Explorer window."
)
public class CapaPlugin extends ProgramPlugin {

    private CapaProvider provider;

    //  Lifecycle                                                           

    public CapaPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new CapaProvider(tool, getName(), this);
    }

    @Override
    protected void programActivated(Program program) {
        provider.onProgramActivated(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        provider.onProgramDeactivated(program);
    }

    //  Analysis entry-point 

    public void runAnalysis(boolean forceRerun) {
        Program program = currentProgram;
        if (program == null) {
            Msg.showInfo(this, null, "Capa Analysis", "No program is currently open.");
            return;
        }

        String rulesDir = CapaCacheManager.readRulesDirectory();
        if (rulesDir == null || rulesDir.isEmpty()) {
            Msg.showInfo(this, null, "Capa Analysis",
                    "No rules directory configured.\n\nClick Settings and select your capa-rules folder.");
            return;
        }

        tool.showComponentProvider(provider, true);

        // Load from cache if available and not forcing rerun
        if (!forceRerun && CapaCacheManager.cacheExists(program)) {
            String json = CapaCacheManager.readCache(program);
            if (json != null) {
                provider.displayResults(json);
                return;
            }
        }

        TaskLauncher.launch(new CapaAnalysisTask(program, rulesDir));
    }
    
    //  Background analysis task


    private class CapaAnalysisTask extends Task {

        private final Program program;
        private final String  rulesDir;

        CapaAnalysisTask(Program program, String rulesDir) {
            super("Running capa analysis", true, false, true);
            this.program  = program;
            this.rulesDir = rulesDir;
        }

        @Override
        public void run(TaskMonitor monitor) {
            provider.showLoading("Running capa analysis\u2026");

            try {
                // Determine the cache file path Python will write to
                String outputPath = CapaCacheManager.getCacheFilePathForPython(program);
                if (outputPath == null) {
                    showError("Could not determine cache file path.");
                    return;
                }

                // Delete stale cache so we can reliably detect new output
                Files.deleteIfExists(Path.of(outputPath));

                // Write both rulesDir and outputPath into config.json
                // so RunCapaMVP.py can read them without recomputing the hash
                CapaCacheManager.writeAnalysisConfig(rulesDir, outputPath);

                // Locate RunCapaMVP.py bundled with this extension
                String scriptPath = resolveScriptPath();
                if (scriptPath == null) {
                    showError("Could not locate RunCapaMVP.py in the extension's ghidra_scripts folder.");
                    return;
                }

                // Invoke via GhidraScriptService — executes inside the PyGhidra environment.
                // The script receives the current Program context automatically.
                monitor.setMessage("Invoking capa via PyGhidra\u2026");
                GhidraScriptService scriptService = tool.getService(GhidraScriptService.class);
                if (scriptService == null) {
                    showError("GhidraScriptService not available. Is PyGhidra installed?");
                    return;
                }

                // GhidraScriptService requires the script to be in a registered
                // script directory. Register our ghidra_scripts folder so it
                // can find RunCapaMVP.py by name.
                File scriptFile = new File(scriptPath);
                ResourceFile scriptDir = new ResourceFile(scriptFile.getParentFile());

                // Add to known script directories if not already present
                if (!GhidraScriptUtil.getScriptSourceDirectories().contains(scriptDir)) {
                    GhidraScriptUtil.getScriptSourceDirectories().add(scriptDir);
                }

                scriptService.runScript("RunCapaMVP.py", new TaskListener() {
                    @Override
                    public void taskCompleted(Task task) {
                        Msg.info(CapaPlugin.this, "[capa] Script completed.");
                    }
                    @Override
                    public void taskCancelled(Task task) {
                        Msg.warn(CapaPlugin.this, "[capa] Script was cancelled.");
                    }
                });

                // Poll for the output file written by Python
                monitor.setMessage("Waiting for capa results\u2026");
                String json = waitForCacheFile(outputPath, monitor);
                if (json == null) {
                    showError("capa did not produce output. Check the Ghidra console for details.");
                    return;
                }

                // Persist to named cache and display in UI
                CapaCacheManager.writeCache(program, json);
                provider.displayResults(json);

            } catch (Exception e) {
                showError("Unexpected error: " + e.getMessage());
                Msg.error(CapaPlugin.this, "capa analysis error", e);
            }
        }

        private String waitForCacheFile(String outputPath, TaskMonitor monitor)
                throws InterruptedException {
            final int MAX_WAIT_MS   = 300_000; // 5 min — capa can be slow on large binaries
            final int POLL_INTERVAL = 500;
            long start = System.currentTimeMillis();

            while (!monitor.isCancelled()) {
                Path p = Path.of(outputPath);
                if (Files.exists(p)) {
                    try {
                        String raw = Files.readString(p, StandardCharsets.UTF_8).trim();
                        // Strip any non-JSON preamble before the opening brace
                        int jsonStart = raw.indexOf('{');
                        if (jsonStart > 0) raw = raw.substring(jsonStart);
                        if (!raw.isEmpty()) return raw;
                    } catch (Exception ignored) {}
                }
                if (System.currentTimeMillis() - start > MAX_WAIT_MS) return null;
                Thread.sleep(POLL_INTERVAL);
            }
            return null;
        }
        
        private String resolveScriptPath() {
            try {
                File jar = new File(
                        getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
                // Extension layout: CapaExplorer/lib/CapaExplorer.jar
                //                   CapaExplorer/ghidra_scripts/RunCapaMVP.py
                File extensionDir = jar.getParentFile().getParentFile();
                File[] candidates = {
                    new File(extensionDir,              "ghidra_scripts/RunCapaMVP.py"),
                    new File(jar.getParentFile(),        "ghidra_scripts/RunCapaMVP.py"),
                    new File(extensionDir,              "ghidra_Scripts/RunCapaMVP.py"),
                };
                for (File f : candidates) {
                    Msg.info(CapaPlugin.this, "Checking script path: " + f.getAbsolutePath());
                    if (f.exists()) return f.getAbsolutePath();
                }
            } catch (Exception e) {
                Msg.warn(CapaPlugin.this, "Could not resolve script path: " + e.getMessage());
            }
            return null;
        }

        private void showError(String msg) {
            provider.showError(msg);
            Msg.showError(CapaPlugin.this, null, "Capa Analysis Error", msg);
        }
    }
}