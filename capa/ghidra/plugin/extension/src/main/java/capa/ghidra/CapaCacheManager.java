package capa.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

/**
 * CapaCacheManager
 *
 * Manages per-program JSON cache files for capa analysis results.
 *
 * Cache location:  {@code <user.home>/.capa_ghidra_cache/<sha256>.json}
 *
 * All public methods are static so they can be called from both Java
 * (CapaPlugin) and from Python via PyGhidra (RunCapaMVP.py / capa_runner.py).
 *
 * Uses only standard Java NIO — no deprecated APIs.
 * Requires Java 11+ (Files.readString, Files.writeString).
 */
public class CapaCacheManager {

    private static final String CACHE_DIR = ".capa_ghidra_cache";

    // ------------------------------------------------------------------
    // Public API — called from both Java and Python
    // ------------------------------------------------------------------

    /**
     * Absolute path to the cache file for this program, as a String.
     * Called from Python: {@code CapaCacheManager.getCacheFilePathForPython(program)}
     */
    public static String getCacheFilePathForPython(Program program) {
        try {
            return cacheFilePath(program).toAbsolutePath().toString();
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class,
                "Failed to compute cache path for " + program.getName(), e);
            return null;
        }
    }

    /** True if a cache file exists for this program. */
    public static boolean cacheExists(Program program) {
        try {
            return Files.exists(cacheFilePath(program));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Read and return the cached JSON string.
     * Returns {@code null} on cache miss or any I/O error.
     */
    public static String readCache(Program program) {
        try {
            Path p = cacheFilePath(program);
            if (!Files.exists(p)) return null;
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class,
                "Failed to read cache for " + program.getName(), e);
            return null;
        }
    }

    /**
     * Atomically write a JSON string to the cache file.
     * Write-to-tmp then rename — safe against partial writes.
     */
    public static boolean writeCache(Program program, String json) {
        try {
            Path target = cacheFilePath(program);
            ensureDir(target.getParent());

            Path tmp = Paths.get(target + ".tmp");
            Files.writeString(tmp, json, StandardCharsets.UTF_8);

            if (Files.exists(target)) Files.delete(target);
            Files.move(tmp, target);
            return true;
        } catch (Exception e) {
            Msg.error(CapaCacheManager.class,
                "Failed to write cache for " + program.getName(), e);
            return false;
        }
    }

    /** Delete the cache file for this program (used by Force Re-run). */
    public static void deleteCache(Program program) {
        try {
            Files.deleteIfExists(cacheFilePath(program));
        } catch (Exception e) {
            Msg.warn(CapaCacheManager.class,
                "Failed to delete cache for " + program.getName() + ": " + e.getMessage());
        }
    }

    /**
     * SHA-256 of {@code executablePath|programName} — stable cache key.
     * Called from Python: {@code CapaCacheManager.computeProgramHash(program)}
     */
    public static String computeProgramHash(Program program) {
        try {
            String key = program.getExecutablePath() + "|" + program.getName();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(key.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            // Fallback — should never happen (SHA-256 is always available)
            return Integer.toHexString(program.getName().hashCode());
        }
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    private static Path cacheFilePath(Program program) throws IOException {
        Path dir = Paths.get(System.getProperty("user.home"), CACHE_DIR);
        ensureDir(dir);
        return dir.resolve(computeProgramHash(program) + ".json");
    }

    private static void ensureDir(Path dir) throws IOException {
        if (!Files.exists(dir)) Files.createDirectories(dir);
    }
}