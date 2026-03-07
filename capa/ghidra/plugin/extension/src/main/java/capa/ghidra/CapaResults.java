package capa.ghidra;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Legacy data class - kept for cache compatibility.
 * New code uses CapaTreeTableModel to parse JSON directly.
 */
public class CapaResults {

    private static final Gson gson = new Gson();

    public String programName;
    public String programPath;
    public String imageBase;
    public String language;
    public String compiler;

    public int functionCount;
    public int externalFunctionCount;
    public String timestamp;
    public String capaVersion;
    public String programHash;

    public List<MemoryBlock> memoryBlocks;
    public List<Capability> capabilities;

    public CapaResults() {
        this.memoryBlocks = new ArrayList<>();
        this.capabilities = new ArrayList<>();
    }

    public static CapaResults fromJson(String json) throws JsonSyntaxException {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (root.has("results")) {
                return gson.fromJson(root.getAsJsonObject("results"), CapaResults.class);
            }
            return gson.fromJson(json, CapaResults.class);
        } catch (Exception e) {
            throw new JsonSyntaxException("Failed to parse capa results: " + e.getMessage(), e);
        }
    }

    public String toJson() {
        return gson.toJson(this);
    }

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