package capa.ghidra;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Capa",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Run capa analysis",
    description = "Capa explorer MVP for Ghidra"
)
public class CapaPlugin extends ProgramPlugin {

    private CapaProvider provider;

    public CapaPlugin(PluginTool tool) {
        super(tool);

        provider = new CapaProvider(tool);
        createActions();
    }

    private void createActions() {

        DockingAction action =
            new DockingAction("Run capa analysis", getName()) {

                @Override
                public void actionPerformed(ActionContext context) {
                    provider.runCapa(currentProgram);
                }
            };

        action.setMenuBarData(
            new MenuData(new String[] {
                "Tools",
                "Run capa analysis"
            })
        );

        tool.addAction(action);
    }
}

