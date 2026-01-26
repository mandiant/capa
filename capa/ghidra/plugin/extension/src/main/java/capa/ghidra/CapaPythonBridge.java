package capa.ghidra;

import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import generic.jar.ResourceFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class CapaPythonBridge {

    public static String run(Program program) throws Exception {

        // data/python/
        ResourceFile pythonDir =
            Application.getModuleDataSubDirectory("python");

        // data/python/capa_runner.py
        File scriptFile =
            new File(pythonDir.getFile(false), "capa_runner.py");

        Process process =
            new ProcessBuilder(
                "python3",
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
                output.append(line).append("\n");
            }
        }

        process.waitFor();
        return output.toString();
    }
}