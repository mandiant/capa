package capa.ghidra;

import com.google.gson.*;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class CapaCacheManager {

    private static final long   MAX_CACHE_SIZE  = 100L * 1024 * 1024; // 100 MB
    private static final String CACHE_DIR_NAME  = "capa_cache";
    private static final String CONFIG_FILE     = "config.json";
    private static final Gson   GSON            = new GsonBuilder().setPrettyPrinting().create();

    //  Cache directory                                                     

    private static Path getCacheDir() throws IOException {
        File userDir = Application.getUserSettingsDirectory();
        Path cacheDir = userDir.toPath().resolve(CACHE_DIR_NAME);
        if (!Files.exists(cacheDir)) {
            Files.createDirectories(cacheDir);
            setPosixPerms(cacheDir, "rwx------");
        }
        return cacheDir;
    }

    //  Per-binary result cache                                             

    public static String computeProgramHash(Program program) {
        try {
            String id = program.getName() + "|" +
                    (program.getExecutablePath() != null ? program.getExecutablePath() : "");
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(id.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(Math.abs(program.getName().hashCode()));
        }
    }

    private static Path getCacheFilePath(String hash) throws IOException {
        if (!hash.matches("^[0-9a-f]+$")) throw new SecurityException("Invalid hash");
        Path dir  = getCacheDir();
        Path file = dir.resolve(hash + ".json");
        if (!file.normalize().startsWith(dir.normalize()))
            throw new SecurityException("Path traversal detected");
        return file;
    }

    public static boolean cacheExists(Program program) {
        try {
            Path f = getCacheFilePath(computeProgramHash(program));
            return Files.exists(f) && Files.size(f) <= MAX_CACHE_SIZE;
        } catch (Exception e) {
            return false;
        }
    }

    public static String readCache(Program program) {
        try {
            Path f = getCacheFilePath(computeProgramHash(program));
            if (!Files.exists(f) || Files.size(f) > MAX_CACHE_SIZE) return null;
            return Files.readString(f, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class, "readCache failed", e);
            return null;
        }
    }

    public static boolean writeCache(Program program, String json) {
        try {
            Path file = getCacheFilePath(computeProgramHash(program));
            Path tmp  = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, json, StandardCharsets.UTF_8);
            setPosixPerms(tmp, "rw-------");
            Files.move(tmp, file,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class, "writeCache failed", e);
            return false;
        }
    }

    public static boolean deleteCache(Program program) {
        try {
            Path f = getCacheFilePath(computeProgramHash(program));
            return Files.deleteIfExists(f);
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class, "deleteCache failed", e);
            return false;
        }
    }


    public static String getCacheFilePathForPython(Program program) {
        try {
            return getCacheFilePath(computeProgramHash(program)).toAbsolutePath().toString();
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class, "getCacheFilePathForPython failed", e);
            return null;
        }
    }

    //  Config — rules directory                                           
    private static Path getConfigFilePath() throws IOException {
        return getCacheDir().resolve(CONFIG_FILE);
    }

    private static JsonObject readConfig() {
        try {
            Path cfg = getConfigFilePath();
            if (!Files.exists(cfg)) return new JsonObject();
            String raw = Files.readString(cfg, StandardCharsets.UTF_8);
            return JsonParser.parseString(raw).getAsJsonObject();
        } catch (Exception e) {
            return new JsonObject();
        }
    }

    private static void writeConfig(JsonObject config) {
        try {
            Path cfg = getConfigFilePath();
            Files.writeString(cfg, GSON.toJson(config), StandardCharsets.UTF_8);
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class, "writeConfig failed", e);
        }
    }

    public static String readRulesDirectory() {
        JsonObject cfg = readConfig();
        // Support both key names for backwards compatibility
        for (String key : new String[]{"rulesDirectory", "rules_directory"}) {
            if (cfg.has(key) && !cfg.get(key).isJsonNull()) {
                String val = cfg.get(key).getAsString().trim();
                if (!val.isEmpty()) return val;
            }
        }
        return null;
    }

    public static void writeRulesDirectory(String path) {
        JsonObject cfg = readConfig();
        cfg.addProperty("rulesDirectory", path);
        // Keep legacy key for any older code
        cfg.addProperty("rules_directory", path);
        writeConfig(cfg);
    }

    public static void writeAnalysisConfig(String rulesDir, String outputPath) {
        JsonObject cfg = readConfig();
        cfg.addProperty("rulesDirectory", rulesDir);
        cfg.addProperty("rules_directory", rulesDir);
        cfg.addProperty("outputPath", outputPath);
        writeConfig(cfg);
    }

    //  Helpers                                                             
    
    private static void setPosixPerms(Path path, String perms) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows — no-op
        }
    }
}