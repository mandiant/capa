package capa.ghidra;

import com.google.gson.*;
import javax.swing.tree.DefaultMutableTreeNode;
import java.util.*;

/**
 * CapaTreeTableModel builds a JTreeTable-compatible model from capa v7+ JSON.
 *
 * Tree structure mirrors the IDA plugin:
 *   Rule name (N matches)  |        | namespace/path
 *     function(sub_XXXX)   | 0xADDR |
 *       and                |        |
 *         api(foo.Bar)     | 0xADDR | call foo.Bar
 *         ...
 *     basic block @ 0xADDR |        |
 *       or                 |        |
 *         number: 0x26     | 0xADDR | mov eax, 0x26
 */
public class CapaResultsTreeModel extends AbstractTreeTableModel {

    private static final String[] COLUMN_NAMES  = {"Rule Information", "Address", "Details"};
    private static final Class<?>[] COLUMN_TYPES = {TreeTableModel.class, String.class, String.class};

    // ------------------------------------------------------------------ //
    //  Construction                                                        //
    // ------------------------------------------------------------------ //

    public CapaResultsTreeModel() {
        super(new DefaultMutableTreeNode(new CapaNodeData("(no results)", "", "")));
    }

    private CapaResultsTreeModel(DefaultMutableTreeNode root) {
        super(root);
    }

    public static CapaResultsTreeModel fromJson(JsonObject capaJson) {
        return new CapaResultsTreeModel(buildTree(capaJson));
    }

    // ------------------------------------------------------------------ //
    //  TreeTableModel column API                                           //
    // ------------------------------------------------------------------ //

    @Override public int    getColumnCount()            { return COLUMN_NAMES.length; }
    @Override public String getColumnName(int col)      { return COLUMN_NAMES[col]; }
    @Override public Class<?> getColumnClass(int col)   { return COLUMN_TYPES[col]; }

    @Override
    public Object getValueAt(Object node, int column) {
        DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) node;
        CapaNodeData data = (CapaNodeData) treeNode.getUserObject();
        switch (column) {
            case 0: return data;          // rendered by JTree column
            case 1: return data.getAddress();
            case 2: return data.getDetails();
            default: return null;
        }
    }

    // ------------------------------------------------------------------ //
    //  TreeModel node API                                                  //
    // ------------------------------------------------------------------ //

    @Override public Object getChild(Object parent, int index) {
        return ((DefaultMutableTreeNode) parent).getChildAt(index);
    }

    @Override public int getChildCount(Object parent) {
        return ((DefaultMutableTreeNode) parent).getChildCount();
    }

    @Override public boolean isLeaf(Object node) {
        return ((DefaultMutableTreeNode) node).isLeaf();
    }

    // ------------------------------------------------------------------ //
    //  JSON → Tree builder                                                  //
    // ------------------------------------------------------------------ //

    private static DefaultMutableTreeNode buildTree(JsonObject capaJson) {
        DefaultMutableTreeNode root =
                new DefaultMutableTreeNode(new CapaNodeData("capa results", "", ""));

        try {
            // capa cache wrapper: { "version", "timestamp", "programHash", "programName", "results": { "rules": {...} } }
            JsonObject payload = capaJson;
            if (capaJson.has("results") && capaJson.get("results").isJsonObject()) {
                payload = capaJson.getAsJsonObject("results");
            }

            JsonObject rules = null;
            for (String key : new String[]{"rules", "rule_matches", "capabilities"}) {
                if (payload.has(key) && payload.get(key).isJsonObject()) {
                    rules = payload.getAsJsonObject(key);
                    break;
                }
            }

            if (rules == null) {
                StringBuilder keys = new StringBuilder("Top-level keys: ");
                for (String k : payload.keySet()) keys.append(k).append(", ");
                root.add(new DefaultMutableTreeNode(
                        new CapaNodeData(keys.toString(), "", "")));
                return root;
            }

            for (Map.Entry<String, JsonElement> ruleEntry : rules.entrySet()) {
                String ruleName = ruleEntry.getKey();
                if (!ruleEntry.getValue().isJsonObject()) continue;
                JsonObject ruleObj = ruleEntry.getValue().getAsJsonObject();

                JsonObject meta = ruleObj.has("meta")
                        ? ruleObj.getAsJsonObject("meta") : new JsonObject();

                String namespace = getStringOr(meta, "namespace", "");

                List<JsonObject> matchList = collectMatches(ruleObj);

                int matchCount = matchList.size();
                if (matchCount == 0) continue;

                String label = matchCount > 1
                        ? ruleName + " (" + matchCount + " matches)"
                        : ruleName;

                DefaultMutableTreeNode ruleNode = new DefaultMutableTreeNode(
                        new CapaNodeData(label, "", namespace, CapaNodeData.NodeType.RULE));

                for (JsonObject match : matchList) {
                    addMatchNode(ruleNode, match);
                }

                root.add(ruleNode);
            }
        } catch (Exception e) {
            root.add(new DefaultMutableTreeNode(
                    new CapaNodeData("Error parsing results: " + e.getMessage(), "", "")));
        }

        return root;
    }

    /**
     * Collect all match objects from a rule, handling both capa JSON formats:
     *   v6:  "matches": [[location, matchDetail], ...]  (array of pairs)
     *   v7+: "matches": { "0x1234": matchDetail, ... }  (object keyed by address)
     */
    private static List<JsonObject> collectMatches(JsonObject ruleObj) {
        List<JsonObject> result = new ArrayList<>();
        if (!ruleObj.has("matches")) return result;

        JsonElement matchesEl = ruleObj.get("matches");

        if (matchesEl.isJsonArray()) {
            // v6 format: array of [location, detail] pairs
            for (JsonElement el : matchesEl.getAsJsonArray()) {
                if (!el.isJsonArray()) continue;
                JsonArray pair = el.getAsJsonArray();
                if (pair.size() < 2 || !pair.get(1).isJsonObject()) continue;
                JsonObject detail = pair.get(1).getAsJsonObject();
                // Inject location into detail for address extraction
                detail.add("_location", pair.get(0));
                result.add(detail);
            }
        } else if (matchesEl.isJsonObject()) {
            // v7+ format: object keyed by address string
            JsonObject matchesObj = matchesEl.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : matchesObj.entrySet()) {
                if (!entry.getValue().isJsonObject()) continue;
                JsonObject detail = entry.getValue().getAsJsonObject().deepCopy();
                // Inject the address key as "_addr" for display
                detail.addProperty("_addr", entry.getKey());
                result.add(detail);
            }
        }
        return result;
    }

    private static void addMatchNode(DefaultMutableTreeNode ruleNode, JsonObject match) {
        // Determine address and scope label
        String addr = "";
        if (match.has("_addr")) {
            addr = match.get("_addr").getAsString();
            // Normalise: if it looks like a plain integer, hex-format it
            try {
                long v = Long.parseUnsignedLong(addr);
                addr = "0x" + Long.toHexString(v).toUpperCase();
            } catch (NumberFormatException ignored) {}
        } else if (match.has("_location")) {
            addr = extractAddress(match.get("_location"));
        }

        // Determine scope type from "node" or presence of sub-matches
        String scopeLabel;
        boolean isFunction = match.has("node") &&
                match.getAsJsonObject("node").has("type") &&
                "function".equals(match.getAsJsonObject("node").get("type").getAsString());

        if (addr.isEmpty()) {
            scopeLabel = "file scope";
        } else if (isFunction) {
            scopeLabel = "function @ " + addr;
        } else {
            scopeLabel = "basic block @ " + addr;
        }

        CapaNodeData.NodeType scopeType = isFunction
                ? CapaNodeData.NodeType.FUNCTION : CapaNodeData.NodeType.BASIC_BLOCK;

        DefaultMutableTreeNode scopeNode = new DefaultMutableTreeNode(
                new CapaNodeData(scopeLabel, addr, "", scopeType));

        // Build statement/feature sub-tree from "node" - pass the scope address for propagation
        // IMPORTANT: Capture the returned node to use as parent for match.children
        DefaultMutableTreeNode topLevelNode = null;
        if (match.has("node")) {
            topLevelNode = buildStatementTree(scopeNode, match.getAsJsonObject("node"), match, addr);
        }

        // Handle "children" - render them recursively as nested Match objects
        // Critical: Use topLevelNode (if not null) as parent for children, not scopeNode
        // This ensures children nest under their parent statement, not as siblings
        if (match.has("children") && match.get("children").isJsonArray()) {
            DefaultMutableTreeNode parentForChildren = (topLevelNode != null) ? topLevelNode : scopeNode;
            for (JsonElement child : match.getAsJsonArray("children")) {
                if (child.isJsonObject()) {
                    JsonObject childMatch = child.getAsJsonObject();
                    // Recursively render child Match under the correct parent node
                    // If match.node created a statement, children nest under that statement
                    // If match.node was only a feature, children nest under scope
                    addMatchNodeRecursive(parentForChildren, childMatch, addr);
                }
            }
        }

        ruleNode.add(scopeNode);
    }

    /**
     * Recursively process a Match object, respecting its node/children hierarchy.
     * Used for rendering nested matches that should be children of a parent statement.
     *
     * @param parent the parent tree node to add this match's nodes under
     * @param match the Match object to render
     * @param scopeAddress the address context from the parent scope
     */
    private static void addMatchNodeRecursive(DefaultMutableTreeNode parent, JsonObject match, String scopeAddress) {
        if (!match.has("node")) return;

        // Process this match's node (statement or feature) and get the node that was created
        DefaultMutableTreeNode nodeJustCreated = buildStatementTree(parent, match.getAsJsonObject("node"), match, scopeAddress);

        // Recursively process children - they should nest under the node we just created, not as siblings
        if (nodeJustCreated != null && match.has("children") && match.get("children").isJsonArray()) {
            for (JsonElement child : match.getAsJsonArray("children")) {
                if (child.isJsonObject()) {
                    // Critical fix: pass nodeJustCreated (not parent) as the parent for children
                    // This ensures nesting: each child statement becomes a child of the parent statement
                    addMatchNodeRecursive(nodeJustCreated, child.getAsJsonObject(), scopeAddress);
                }
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Statement / feature recursive builder                               //
    // ------------------------------------------------------------------ //

    private static DefaultMutableTreeNode buildStatementTree(DefaultMutableTreeNode parent,
                                            JsonObject node,
                                            JsonObject matchDetail,
                                            String scopeAddress) {
        if (node == null) return null;

        String nodeType = getStringOr(node, "type", "");

        if ("statement".equals(nodeType)) {
            JsonObject stmt = node.has("statement") ? node.getAsJsonObject("statement") : node;
            String stmtType = getStringOr(stmt, "type", "and").toLowerCase();

            // Statement nodes inherit address from their scope (function/basicblock)
            DefaultMutableTreeNode stmtNode = new DefaultMutableTreeNode(
                    new CapaNodeData(stmtType, scopeAddress, "", CapaNodeData.NodeType.STATEMENT));

            // Recurse into children - get children from the STATEMENT node itself, not matchDetail
            JsonArray children = stmt.has("children")
                    ? stmt.getAsJsonArray("children") : new JsonArray();
            for (JsonElement child : children) {
                if (!child.isJsonObject()) continue;
                JsonObject childObj = child.getAsJsonObject();
                if (childObj.has("node")) {
                    // Capture the returned node in case it's a statement that could have further children
                    // This ensures proper nesting of nested statements
                    DefaultMutableTreeNode childNode = buildStatementTree(stmtNode,
                            childObj.getAsJsonObject("node"), matchDetail, scopeAddress);
                    // childNode contains the created statement/feature node for further processing if needed
                }
            }

            parent.add(stmtNode);
            return stmtNode;  // Return the statement node so it can be used as parent for Match children

        } else if ("feature".equals(nodeType)) {
            JsonObject feature = node.has("feature") ? node.getAsJsonObject("feature") : node;
            
            // Extract feature's own address from the node's location field (replaces scope address)
            String featureAddress = extractAddress(node.get("location"));
            // If feature has no explicit location, fall back to scope address
            if (featureAddress.isEmpty()) {
                featureAddress = scopeAddress;
            }
            
            addFeatureNode(parent, feature, matchDetail, featureAddress);
            return null;  // Features are leaves, return null
        }
        return null;
    }

    private static void addFeatureNode(DefaultMutableTreeNode parent,
                                        JsonObject feature,
                                        JsonObject matchDetail,
                                        String featureAddress) {
    	String featureLabel = renderFeature(feature);
        String details = buildFeatureDetails(feature, matchDetail);

        // Create feature node with its own address (extracted from feature's location in buildStatementTree)
        parent.add(new DefaultMutableTreeNode(
                new CapaNodeData(featureLabel, featureAddress, details)));
    }


    /**
     * Build contextual details for a feature based on its type.
     * Returns strings like:
     *   "call CreateFileA"
     *   "\"cmd.exe\""
     *   "mov eax, 0x26"
     */
    private static String buildFeatureDetails(JsonObject feature, JsonObject matchDetail) {
        String type = getStringOr(feature, "type", "");

        // For api features, try to show call site context
        if ("api".equals(type)) {
            if (matchDetail.has("captures")) {
                JsonObject captures = matchDetail.getAsJsonObject("captures");
                if (captures.has("call")) {
                    return "call " + captures.get("call").getAsString();
                }
            }
            // Extract just the function name for display
            String apiName = getStringOr(feature, "api", "");
            if (!apiName.isEmpty()) {
                return "call " + apiName;
            }
        }

        // For string features, show the string value with quotes
        if ("string".equals(type)) {
            String strValue = getStringOr(feature, "string", "");
            if (!strValue.isEmpty()) {
                return "\"" + strValue + "\"";
            }
        }

        // For number features, show the numeric value
        if ("number".equals(type)) {
            String numValue = getStringOr(feature, "number", "");
            if (!numValue.isEmpty()) {
                // Try to show context like "mov eax, 0x26"
                if (matchDetail.has("captures")) {
                    JsonObject captures = matchDetail.getAsJsonObject("captures");
                    if (captures.size() > 0) {
                        // Get first capture as context
                        for (String key : captures.keySet()) {
                            String context = captures.get(key).getAsString();
                            if (!context.isEmpty()) {
                                return context;
                            }
                        }
                    }
                }
                return numValue;
            }
        }

        // For mnemonic features, show the instruction
        if ("mnemonic".equals(type)) {
            String mnem = getStringOr(feature, "mnemonic", "");
            if (!mnem.isEmpty()) {
                // Try to show full instruction from captures
                if (matchDetail.has("captures")) {
                    JsonObject captures = matchDetail.getAsJsonObject("captures");
                    for (String key : captures.keySet()) {
                        String instr = captures.get(key).getAsString();
                        if (!instr.isEmpty()) {
                            return instr;
                        }
                    }
                }
                return mnem;
            }
        }

        // For regex features, show the regex pattern
        if ("regex".equals(type)) {
            String regexVal = getStringOr(feature, "regex", "");
            if (!regexVal.isEmpty()) {
                return regexVal;
            }
        }

        // For bytes features, show hex dump
        if ("bytes".equals(type)) {
            String bytesVal = getStringOr(feature, "bytes", "");
            if (!bytesVal.isEmpty()) {
                return bytesVal;
            }
        }

        // For characteristic, show the characteristic name
        if ("characteristic".equals(type)) {
            String charVal = getStringOr(feature, "characteristic", "");
            if (!charVal.isEmpty()) {
                return charVal;
            }
        }

        // For import/export/section, show the name
        if ("import".equals(type) || "export".equals(type) || "section".equals(type)) {
            String val = getStringOr(feature, type, "");
            if (!val.isEmpty()) {
                return val;
            }
        }

        // Fallback: try to find any meaningful capture
        if (matchDetail.has("captures")) {
            JsonObject captures = matchDetail.getAsJsonObject("captures");
            for (String key : captures.keySet()) {
                String val = captures.get(key).getAsString();
                if (!val.isEmpty() && val.length() < 100) {
                    return val;
                }
            }
        }

        return "";
    }

    // ------------------------------------------------------------------ //
    //  Helpers                                                             //
    // ------------------------------------------------------------------ //
    /**
     * Render a feature using capa's canonical string representation.
     * This mimics the Python Feature.__str__() output.
     */
    private static String renderFeature(JsonObject feature) {

        String type = getStringOr(feature, "type", "");

        switch (type) {

            case "api":
                return "api(" + getStringOr(feature, "api", "") + ")";

            case "string":
                return "string(\"" + getStringOr(feature, "string", "") + "\")";

            case "number":
                return "number(" + getStringOr(feature, "number", "") + ")";

            case "regex":
                return "regex(" + getStringOr(feature, "regex", "") + ")";

            case "mnemonic":
                return "mnemonic(" + getStringOr(feature, "mnemonic", "") + ")";

            case "characteristic":
                return "characteristic(" +
                        getStringOr(feature, "characteristic", "") + ")";

            case "import":
                return "import(" + getStringOr(feature, "import", "") + ")";

            case "export":
                return "export(" + getStringOr(feature, "export", "") + ")";

            case "section":
                return "section(" + getStringOr(feature, "section", "") + ")";

            case "bytes":
                return "bytes(" + getStringOr(feature, "bytes", "") + ")";

            case "offset":
                return "offset(" + getStringOr(feature, "offset", "") + ")";

            default:
                if (feature.has("value")) {
                    return type + "(" + feature.get("value").getAsString() + ")";
                }
                return type;
        }
    }
    private static String extractAddress(JsonElement locEl) {
        if (locEl == null || locEl.isJsonNull()) return "";
        try {
            if (locEl.isJsonObject()) {
                JsonObject loc = locEl.getAsJsonObject();
                if (loc.has("value")) {
                    long val = loc.get("value").getAsLong();
                    return "0x" + Long.toHexString(val).toUpperCase();
                }
            }
            // plain string address
            if (locEl.isJsonPrimitive()) {
                String s = locEl.getAsString();
                if (s.startsWith("0x") || s.startsWith("0X")) return s.toUpperCase();
                long val = Long.parseUnsignedLong(s);
                return "0x" + Long.toHexString(val).toUpperCase();
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String getStringOr(JsonObject obj, String key, String fallback) {
        if (obj != null && obj.has(key) && !obj.get(key).isJsonNull()) {
            try { return obj.get(key).getAsString(); } catch (Exception ignored) {}
        }
        return fallback;
    }
}