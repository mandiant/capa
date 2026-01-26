package capa.ghidra;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Capa",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Run capa analysis",
    description = "Capa explorer MVP for Ghidra"
)
public class CapaPlugin extends ProgramPlugin {

    private DockingAction action;
    private CapaProvider provider;

    public CapaPlugin(PluginTool tool) {
        super(tool);

        provider = new CapaProvider(tool);
        createActions();
    }

    private void createActions() {

        action = new DockingAction("Run capa analysis", getName()) {

            @Override
            public void actionPerformed(ActionContext context) {

                Msg.showInfo(
                    this,
                    null,
                    "CapaPlugin",
                    "Run capa analysis clicked"
                );

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