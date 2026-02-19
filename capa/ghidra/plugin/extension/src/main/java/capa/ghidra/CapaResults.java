package capa.ghidra;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Data class representing capa analysis results.
 */
public class CapaResults {
    
    private static final Gson gson = new Gson();
    
    // Basic program info
    public String programName;
    public String programPath;
    public String imageBase;
    public String language;
    public String compiler;
    
    // Analysis metadata
    public int functionCount;
    public int externalFunctionCount;
    public String timestamp;
    public String capaVersion;
    public String programHash;
    
    // Memory blocks
    public List<MemoryBlock> memoryBlocks;
    
    // Capabilities (will be populated with real capa data later)
    public List<Capability> capabilities;
    
    public CapaResults() {
        this.memoryBlocks = new ArrayList<>();
        this.capabilities = new ArrayList<>();
    }
    
    /**
     * Parse JSON string into CapaResults object.
     * Handles the cache wrapper structure from Python.
     */
    public static CapaResults fromJson(String json) throws JsonSyntaxException {
        try {
            // Parse the JSON
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            
            // The cache structure is: {"version": "1.0", "results": {...}}
            // Extract the "results" object
            if (root.has("results")) {
                JsonObject resultsObj = root.getAsJsonObject("results");
                return gson.fromJson(resultsObj, CapaResults.class);
            } else {
                // If no "results" wrapper, try parsing directly
                return gson.fromJson(json, CapaResults.class);
            }
            
        } catch (Exception e) {
            throw new JsonSyntaxException("Failed to parse capa results: " + e.getMessage(), e);
        }
    }
    
    /**
     * Convert to JSON string.
     */
    public String toJson() {
        return gson.toJson(this);
    }
    
    /**
     * Memory block info.
     */
    public static class MemoryBlock {
        public String name;
        public String start;
        public String end;
        public long size;
        public Permissions permissions;
        
        public static class Permissions {
            public boolean read;
            public boolean write;
            public boolean execute;
        }
    }
    
    /**
     * Capability detection result.
     * (Structure will be refined when real capa is integrated)
     */
    public static class Capability {
        public String name;
        public String namespace;
        public String description;
        public List<Match> matches;
        
        public Capability() {
            this.matches = new ArrayList<>();
        }
        
        public static class Match {
            public String address;
            public String function;
            public String details;
        }
    }
}
