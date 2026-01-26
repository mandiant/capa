package capa.ghidra;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class CapaPythonBridge {
	/**
	 * Execute capa analysis for the currently loaded program.
	 *
	 * NOTE: The Program parameter is intentionally unused in this MVP.
	 * In future iterations, program metadata (path, architecture, hashes,
	 * memory layout, etc.) will be passed to the Python capa runner.
	 */

    public static String run(Program program) throws Exception {

        ResourceFile pythonDir =
            Application.getModuleDataSubDirectory("python");

        File scriptFile =
            new File(
                pythonDir.getFile(false),
                "capa_runner.py"
            );

        String python = System.getenv("CAPA_PYTHON");
        if (python == null || python.isBlank()) {
            python = "python3";
        }

        Msg.info(
            CapaPythonBridge.class,
            "Using Python executable: " + python
        );

        Process process =
            new ProcessBuilder(
                python,
                scriptFile.getAbsolutePath()
            )
            .redirectErrorStream(true)
            .start();

        StringBuilder output = new StringBuilder();

        try (BufferedReader reader =
                 new BufferedReader(
                     new InputStreamReader(
                         process.getInputStream()))) {

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }

        int exit = process.waitFor();
        if (exit != 0) {
            throw new RuntimeException(
                "Python exited with code " + exit
            );
        }

        return output.toString();
    }
}
