package capa.ghidra;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Shared container for exchanging capa results between PyGhidra scripts and Java.
 * Thread-safe for concurrent access.
 */
public class CapaResultsContainer {
    
    private static final Map<String, String> resultsCache = new ConcurrentHashMap<>();
    
    /**
     * Store analysis results for a program.
     * Called from Python via PyGhidra.
     */
    public static synchronized void storeResults(String programHash, String jsonResults) {
        resultsCache.put(programHash, jsonResults);
        System.out.println("[CapaResultsContainer] Stored results for: " + programHash);
    }
    
    /**
     * Retrieve analysis results for a program.
     */
    public static synchronized String getResults(String programHash) {
        return resultsCache.get(programHash);
    }
    
    /**
     * Check if results exist.
     */
    public static synchronized boolean hasResults(String programHash) {
        return resultsCache.containsKey(programHash);
    }
    
    /**
     * Clear results for a program.
     */
    public static synchronized void clearResults(String programHash) {
        resultsCache.remove(programHash);
        System.out.println("[CapaResultsContainer] Cleared results for: " + programHash);
    }
}
