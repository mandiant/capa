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

        // Build statement/feature sub-tree from "node"
        if (match.has("node")) {
            buildStatementTree(scopeNode, match.getAsJsonObject("node"), match);
        }

        // Handle "children" directly on the match (v7 format)
        if (match.has("children") && match.get("children").isJsonArray()) {
            for (JsonElement child : match.getAsJsonArray("children")) {
                if (child.isJsonObject()) {
                    JsonObject childObj = child.getAsJsonObject();
                    if (childObj.has("node")) {
                        buildStatementTree(scopeNode, childObj.getAsJsonObject("node"), childObj);
                    }
                }
            }
        }

        ruleNode.add(scopeNode);
    }

    // ------------------------------------------------------------------ //
    //  Statement / feature recursive builder                               //
    // ------------------------------------------------------------------ //

    private static void buildStatementTree(DefaultMutableTreeNode parent,
                                            JsonObject node,
                                            JsonObject matchDetail) {
        if (node == null) return;

        String nodeType = getStringOr(node, "type", "");

        if ("statement".equals(nodeType)) {
            JsonObject stmt = node.has("statement") ? node.getAsJsonObject("statement") : node;
            String stmtType = getStringOr(stmt, "type", "and").toLowerCase();

            DefaultMutableTreeNode stmtNode = new DefaultMutableTreeNode(
                    new CapaNodeData(stmtType, "", "", CapaNodeData.NodeType.STATEMENT));

            // Recurse into children
            JsonArray children = matchDetail.has("children")
                    ? matchDetail.getAsJsonArray("children") : new JsonArray();
            for (JsonElement child : children) {
                if (!child.isJsonObject()) continue;
                JsonObject childObj = child.getAsJsonObject();
                if (childObj.has("node")) {
                    buildStatementTree(stmtNode,
                            childObj.getAsJsonObject("node"), childObj);
                }
            }

            parent.add(stmtNode);

        } else if ("feature".equals(nodeType)) {
            JsonObject feature = node.has("feature") ? node.getAsJsonObject("feature") : node;
            addFeatureNode(parent, feature, matchDetail);
        }
    }

    private static void addFeatureNode(DefaultMutableTreeNode parent,
                                        JsonObject feature,
                                        JsonObject matchDetail) {
    	String featureLabel = renderFeature(feature);
        String addr = "";
        String details = "";

        // Extract the match address from the locations array
        if (matchDetail.has("locations")) {
            JsonArray locs = matchDetail.getAsJsonArray("locations");
            if (locs.size() > 0) {
                addr = extractAddress(locs.get(0));
            }
        }

//        switch (featureType) {
//            case "api":
//                featureLabel = "api: " + getStringOr(feature, "api", "");
//                details = buildCallDetail(matchDetail);
//                break;
//            case "string":
//                featureLabel = "string: " + quote(getStringOr(feature, "string", ""));
//                details = buildCallDetail(matchDetail);
//                break;
//            case "number":
//                String numVal = getStringOr(feature, "number", "");
//                String numDesc = getStringOr(feature, "description", "");
//                featureLabel = "number: " + numVal + (numDesc.isEmpty() ? "" : " = " + numDesc);
//                details = buildCallDetail(matchDetail);
//                break;
//            case "regex":
//                featureLabel = "regex: " + getStringOr(feature, "regex", "");
//                details = buildCallDetail(matchDetail);
//                break;
//            case "bytes":
//                featureLabel = "bytes: " + getStringOr(feature, "bytes", "");
//                break;
//            case "offset":
//                featureLabel = "offset: " + getStringOr(feature, "offset", "");
//                break;
//            case "mnemonic":
//                featureLabel = "mnemonic: " + getStringOr(feature, "mnemonic", "");
//                details = buildCallDetail(matchDetail);
//                break;
//            case "characteristic":
//                featureLabel = "characteristic: " + getStringOr(feature, "characteristic", "");
//                break;
//            case "export":
//                featureLabel = "export: " + getStringOr(feature, "export", "");
//                break;
//            case "import":
//                featureLabel = "import: " + getStringOr(feature, "import", "");
//                break;
//            case "section":
//                featureLabel = "section: " + getStringOr(feature, "section", "");
//                break;
//            default:
//                // Fallback: show type and whatever value is present
//                featureLabel = featureType.isEmpty() ? "(feature)" : featureType;
//                if (feature.has("value")) {
//                    featureLabel += ": " + feature.get("value").getAsString();
//                }
        //}

        details = buildCallDetail(matchDetail);

        parent.add(new DefaultMutableTreeNode(
                new CapaNodeData(featureLabel, addr, details)));
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

//    private static String buildCallDetail(JsonObject matchDetail) {
//        if (matchDetail.has("captures")) {
//            JsonObject cap = matchDetail.getAsJsonObject("captures");
//            if (cap.size() > 0) return cap.keySet().iterator().next();
//        }
//        return "";
//    }
    
//    private static String buildCallDetail(JsonObject matchDetail) {
//
//        // Prefer captures (used by some capa features)
//        if (matchDetail.has("captures")) {
//            JsonObject cap = matchDetail.getAsJsonObject("captures");
//            if (cap.size() > 0) {
//                return cap.keySet().iterator().next();
//            }
//        }
//
//        // Fallback: show address if available
//        if (matchDetail.has("locations")) {
//            JsonArray locs = matchDetail.getAsJsonArray("locations");
//            if (locs.size() > 0) {
//                return extractAddress(locs.get(0));
//            }
//        }
//
//        return "";
//    }
    
    private static String buildCallDetail(JsonObject matchDetail) {
        // Priority 1: Show capture values (these are the most meaningful)
        if (matchDetail.has("captures")) {
            JsonObject cap = matchDetail.getAsJsonObject("captures");
            if (cap.size() > 0) {
                // Get first capture key-value pair
                for (Map.Entry<String, JsonElement> entry : cap.entrySet()) {
                    String key = entry.getKey();
                    JsonElement value = entry.getValue();
                    
                    // Format the capture nicely
                    if (value.isJsonPrimitive()) {
                        String valStr = value.getAsString();
                        // For API calls, imports, etc - just show the name
                        if (key.equals("api") || key.equals("import") || key.equals("export")) {
                            return valStr;
                        }
                        // For strings, quote them
                        if (key.equals("string")) {
                            return "\"" + valStr + "\"";
                        }
                        // For numbers, show as-is
                        if (key.equals("number")) {
                            return valStr;
                        }
                        // Default: show key = value
                        return valStr;
                    }
                    break; // Just use first capture
                }
            }
        }

        // Priority 2: Show instruction disassembly if available
        if (matchDetail.has("instruction")) {
            JsonObject ins = matchDetail.getAsJsonObject("instruction");
            
            // Try to build a simple disassembly: "mnemonic operands"
            StringBuilder disasm = new StringBuilder();
            
            if (ins.has("mnemonic")) {
                disasm.append(ins.get("mnemonic").getAsString());
            }
            
            // Add operands if available
            if (ins.has("operands") && ins.get("operands").isJsonArray()) {
                JsonArray ops = ins.getAsJsonArray("operands");
                if (ops.size() > 0) {
                    disasm.append(" ");
                    for (int i = 0; i < ops.size(); i++) {
                        if (i > 0) disasm.append(", ");
                        JsonElement op = ops.get(i);
                        if (op.isJsonPrimitive()) {
                            disasm.append(op.getAsString());
                        } else if (op.isJsonObject()) {
                            JsonObject opObj = op.getAsJsonObject();
                            if (opObj.has("value")) {
                                disasm.append(opObj.get("value").getAsString());
                            }
                        }
                    }
                }
            } else if (ins.has("operand_str")) {
                // Some capa versions may have a pre-formatted operand string
                disasm.append(" ").append(ins.get("operand_str").getAsString());
            }
            
            if (disasm.length() > 0) {
                return disasm.toString();
            }
        }

        // Priority 3: For feature-level matches, show the feature type/context
        if (matchDetail.has("type")) {
            String type = matchDetail.get("type").getAsString();
            if ("string".equals(type) && matchDetail.has("value")) {
                return "\"" + matchDetail.get("value").getAsString() + "\"";
            }
            if ("number".equals(type) && matchDetail.has("value")) {
                return matchDetail.get("value").getAsString();
            }
        }

        return "";
    }
    
    private static String getStringOr(JsonObject obj, String key, String fallback) {
        if (obj != null && obj.has(key) && !obj.get(key).isJsonNull()) {
            try { return obj.get(key).getAsString(); } catch (Exception ignored) {}
        }
        return fallback;
    }
}