package capa.ghidra;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Secure cache manager for capa analysis results.
 */
public class CapaCacheManager {
    
    private static final long MAX_CACHE_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    private static final String CACHE_VERSION = "1.0";
    private static final String CACHE_DIR_NAME = "capa_cache";
    
    /**
     * Get the secure cache directory path.
     */
    /**
     * Get the secure cache directory path.
     */
    private static Path getCacheBaseDirectory() throws IOException {
        // Use Ghidra's user settings directory (works for any version)
        File userSettingsDir = Application.getUserSettingsDirectory();
        Path cacheDir = userSettingsDir.toPath().resolve(CACHE_DIR_NAME);
        
        if (!Files.exists(cacheDir)) {
            Files.createDirectories(cacheDir);
            
            try {
                Files.setPosixFilePermissions(cacheDir, 
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            } catch (UnsupportedOperationException e) {
                Msg.debug(CapaCacheManager.class, "POSIX permissions not supported");
            }
        }
        
        return cacheDir;
    }
    
    /**
     * Compute SHA-256 hash of program for cache identification.
     */
    public static String computeProgramHash(Program program) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            String identifier = program.getName() + "|" + 
                               (program.getExecutablePath() != null ? program.getExecutablePath() : "");
            
            byte[] hashBytes = digest.digest(identifier.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
            
        } catch (NoSuchAlgorithmException e) {
            Msg.error(CapaCacheManager.class, "SHA-256 not available", e);
            return String.valueOf(program.getName().hashCode());
        }
    }
    
    /**
     * Get the cache file path for a program.
     */
    private static Path getCacheFilePath(String programHash) throws IOException {
        if (!programHash.matches("^[0-9a-f]+$")) {
            throw new SecurityException("Invalid program hash format");
        }
        
        Path cacheDir = getCacheBaseDirectory();
        Path cacheFile = cacheDir.resolve(programHash + ".json");
        
        if (!cacheFile.normalize().startsWith(cacheDir.normalize())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        return cacheFile;
    }
    
    /**
     * Check if a valid cache exists for the program.
     */
    public static boolean cacheExists(Program program) {
        try {
            String programHash = computeProgramHash(program);
            Path cacheFile = getCacheFilePath(programHash);
            
            if (!Files.exists(cacheFile)) {
                return false;
            }
            
            long fileSize = Files.size(cacheFile);
            if (fileSize > MAX_CACHE_FILE_SIZE) {
                Msg.warn(CapaCacheManager.class, "Cache file exceeds size limit");
                return false;
            }
            
            return true;
            
        } catch (IOException | SecurityException e) {
            Msg.error(CapaCacheManager.class, "Error checking cache", e);
            return false;
        }
    }
    
    /**
     * Read cache file and return JSON string.
     */
    public static String readCache(Program program) {
        try {
            String programHash = computeProgramHash(program);
            Path cacheFile = getCacheFilePath(programHash);
            
            if (!Files.exists(cacheFile)) {
                return null;
            }
            
            long fileSize = Files.size(cacheFile);
            if (fileSize > MAX_CACHE_FILE_SIZE) {
                throw new IOException("Cache file too large: " + fileSize + " bytes");
            }
            
            return Files.readString(cacheFile, StandardCharsets.UTF_8);
            
        } catch (IOException | SecurityException e) {
            Msg.error(CapaCacheManager.class, "Error reading cache", e);
            return null;
        }
    }
    
    /**
     * Write cache file with JSON data.
     */
    public static boolean writeCache(Program program, String jsonData) {
        try {
            String programHash = computeProgramHash(program);
            Path cacheFile = getCacheFilePath(programHash);
            
            // Write atomically
            Path tempFile = cacheFile.resolveSibling(cacheFile.getFileName() + ".tmp");
            Files.writeString(tempFile, jsonData, StandardCharsets.UTF_8);
            
            // Set permissions (Unix only)
            try {
                Files.setPosixFilePermissions(tempFile,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                // Windows - ignore
            }
            
            // Atomic move
            Files.move(tempFile, cacheFile, StandardCopyOption.REPLACE_EXISTING, 
                      StandardCopyOption.ATOMIC_MOVE);
            
            Msg.info(CapaCacheManager.class, "Cache written: " + cacheFile.getFileName());
            return true;
            
        } catch (IOException | SecurityException e) {
            Msg.error(CapaCacheManager.class, "Error writing cache", e);
            return false;
        }
    }
    
    /**
     * Get the cache file path for Python to write to.
     */
    public static String getCacheFilePathForPython(Program program) {
        try {
            String programHash = computeProgramHash(program);
            Path cacheFile = getCacheFilePath(programHash);
            
            return cacheFile.toAbsolutePath().toString();
            
        } catch (IOException | SecurityException e) {
            Msg.error(CapaCacheManager.class, "Error getting cache path", e);
            return null;
        }
    }
    
    /**
     * Delete cache for a program.
     */
    public static boolean deleteCache(Program program) {
        try {
            String programHash = computeProgramHash(program);
            Path cacheFile = getCacheFilePath(programHash);
            
            if (Files.exists(cacheFile)) {
                Files.delete(cacheFile);
                Msg.info(CapaCacheManager.class, "Deleted cache: " + cacheFile.getFileName());
                return true;
            }
            
            return false;
            
        } catch (IOException | SecurityException e) {
            Msg.error(CapaCacheManager.class, "Error deleting cache", e);
            return false;
        }
    }
}
