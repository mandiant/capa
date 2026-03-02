package capa.ghidra;

import com.google.gson.*;
import java.util.*;


public class CapaResults {

    public String programName = "", md5 = "", sha256 = "", os = "",
                  arch = "", format = "", language = "";
    public int functionCount = 0;
    public Map<String, Rule> rules = new LinkedHashMap<>();

    public static class Rule {
        public RuleMeta meta = new RuleMeta();
        public String source = "";
        public List<MatchEntry> matches = new ArrayList<>();
    }

    public static class RuleMeta {
        public String name = "", namespace = "", scope = "";
        public List<String> authors = new ArrayList<>(), references = new ArrayList<>();
        public List<Attack> attack = new ArrayList<>();
        public List<Mbc> mbc = new ArrayList<>();
    }

    public static class Attack {
        public List<String> parts = new ArrayList<>();
        public String technique = "", subtechnique = "";
    }

    public static class Mbc {
        public List<String> parts = new ArrayList<>();
        public String objective = "", behavior = "";
    }

    public static class MatchEntry {
        public String address;
        public Match match;
        public MatchEntry(String a, Match m) { address = a; match = m; }
    }

    public static class Match {
        public MatchNode node;
        public boolean success = false;
        public List<String> locations = new ArrayList<>();
        public Map<String, List<String>> captures = new LinkedHashMap<>();
        public List<Match> children = new ArrayList<>();
    }

    public static class MatchNode {
        public String nodeType;
        public String statementType, statementDescription;
        public String featureType, featureValue, featureDescription;

        public String label() {
            if ("statement".equals(nodeType)) {
                String t = statementType != null ? statementType : "?";
                return (statementDescription != null && !statementDescription.isEmpty())
                    ? t + ": " + statementDescription : t;
            }
            if ("feature".equals(nodeType)) {
                StringBuilder sb = new StringBuilder();
                if (featureType  != null && !featureType.isEmpty())  sb.append(featureType).append(": ");
                if (featureValue != null && !featureValue.isEmpty()) sb.append(featureValue);
                if (featureDescription != null && !featureDescription.isEmpty())
                    sb.append("  (").append(featureDescription).append(")");
                return sb.length() > 0 ? sb.toString() : "?";
            }
            return "?";
        }
    }

    public static CapaResults fromJson(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        CapaResults res = new CapaResults();

        if (root.has("meta") && root.get("meta").isJsonObject()) {
            JsonObject meta = root.getAsJsonObject("meta");
            if (meta.has("sample") && meta.get("sample").isJsonObject()) {
                JsonObject s = meta.getAsJsonObject("sample");
                res.programName = str(s, "filename");
                res.md5 = str(s, "md5");
                res.sha256 = str(s, "sha256");
            }
            if (meta.has("analysis") && meta.get("analysis").isJsonObject()) {
                JsonObject a = meta.getAsJsonObject("analysis");
                res.os = str(a, "os"); res.arch = str(a, "arch"); res.format = str(a, "format");
                if (a.has("feature_counts") && a.get("feature_counts").isJsonObject()) {
                    JsonObject fc = a.getAsJsonObject("feature_counts");
                    res.functionCount = fc.has("functions") ? fc.get("functions").getAsInt() : 0;
                }
            }
        }

        if (root.has("rules") && root.get("rules").isJsonObject())
            for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("rules").entrySet())
                if (e.getValue().isJsonObject())
                    res.rules.put(e.getKey(), parseRule(e.getValue().getAsJsonObject()));

        return res;
    }

    private static Rule parseRule(JsonObject obj) {
        Rule rule = new Rule();
        if (obj.has("meta") && obj.get("meta").isJsonObject())
            rule.meta = parseRuleMeta(obj.getAsJsonObject("meta"));
        if (obj.has("source") && obj.get("source").isJsonPrimitive())
            rule.source = obj.get("source").getAsString();
        if (obj.has("matches") && obj.get("matches").isJsonArray())
            for (JsonElement elem : obj.getAsJsonArray("matches"))
                if (elem.isJsonArray()) {
                    JsonArray pair = elem.getAsJsonArray();
                    if (pair.size() >= 2 && pair.get(1).isJsonObject())
                        rule.matches.add(new MatchEntry(parseAddress(pair.get(0)),
                                                        parseMatch(pair.get(1).getAsJsonObject())));
                }
        return rule;
    }

    private static RuleMeta parseRuleMeta(JsonObject obj) {
        RuleMeta m = new RuleMeta();
        m.name = str(obj, "name"); m.namespace = str(obj, "namespace"); m.scope = str(obj, "scope");
        if (obj.has("authors") && obj.get("authors").isJsonArray())
            for (JsonElement a : obj.getAsJsonArray("authors"))
                if (a.isJsonPrimitive()) m.authors.add(a.getAsString());
        if (obj.has("references") && obj.get("references").isJsonArray())
            for (JsonElement r : obj.getAsJsonArray("references"))
                if (r.isJsonPrimitive()) m.references.add(r.getAsString());
        if (obj.has("attack") && obj.get("attack").isJsonArray())
            for (JsonElement a : obj.getAsJsonArray("attack"))
                if (a.isJsonObject()) { Attack atk = new Attack();
                    atk.technique = str(a.getAsJsonObject(), "technique");
                    atk.subtechnique = str(a.getAsJsonObject(), "subtechnique");
                    if (a.getAsJsonObject().has("parts") && a.getAsJsonObject().get("parts").isJsonArray())
                        for (JsonElement p : a.getAsJsonObject().getAsJsonArray("parts"))
                            if (p.isJsonPrimitive()) atk.parts.add(p.getAsString());
                    m.attack.add(atk); }
        if (obj.has("mbc") && obj.get("mbc").isJsonArray())
            for (JsonElement b : obj.getAsJsonArray("mbc"))
                if (b.isJsonObject()) { Mbc mbc = new Mbc();
                    mbc.objective = str(b.getAsJsonObject(), "objective");
                    mbc.behavior = str(b.getAsJsonObject(), "behavior");
                    if (b.getAsJsonObject().has("parts") && b.getAsJsonObject().get("parts").isJsonArray())
                        for (JsonElement p : b.getAsJsonObject().getAsJsonArray("parts"))
                            if (p.isJsonPrimitive()) mbc.parts.add(p.getAsString());
                    m.mbc.add(mbc); }
        return m;
    }

    private static Match parseMatch(JsonObject obj) {
        Match match = new Match();
        match.success = obj.has("success") && obj.get("success").getAsBoolean();
        if (obj.has("node") && obj.get("node").isJsonObject())
            match.node = parseMatchNode(obj.getAsJsonObject("node"));
        if (obj.has("locations") && obj.get("locations").isJsonArray())
            for (JsonElement loc : obj.getAsJsonArray("locations")) match.locations.add(parseAddress(loc));
        if (obj.has("captures") && obj.get("captures").isJsonObject())
            for (Map.Entry<String, JsonElement> e : obj.getAsJsonObject("captures").entrySet()) {
                List<String> locs = new ArrayList<>();
                if (e.getValue().isJsonArray())
                    for (JsonElement loc : e.getValue().getAsJsonArray()) locs.add(parseAddress(loc));
                match.captures.put(e.getKey(), locs);
            }
        if (obj.has("children") && obj.get("children").isJsonArray())
            for (JsonElement child : obj.getAsJsonArray("children"))
                if (child.isJsonObject()) match.children.add(parseMatch(child.getAsJsonObject()));
        return match;
    }

    private static MatchNode parseMatchNode(JsonObject obj) {
        MatchNode node = new MatchNode();
        node.nodeType = str(obj, "type");
        if ("statement".equals(node.nodeType) && obj.has("statement") && obj.get("statement").isJsonObject()) {
            JsonObject stmt = obj.getAsJsonObject("statement");
            node.statementType = str(stmt, "type"); node.statementDescription = str(stmt, "description");
        } else if ("feature".equals(node.nodeType) && obj.has("feature") && obj.get("feature").isJsonObject()) {
            JsonObject feat = obj.getAsJsonObject("feature");
            node.featureType = str(feat, "type"); node.featureDescription = str(feat, "description");
            if (node.featureType != null && !node.featureType.isEmpty() && feat.has(node.featureType)) {
                JsonElement val = feat.get(node.featureType);
                node.featureValue = val.isJsonPrimitive() ? val.getAsString() : val.toString();
            }
        }
        return node;
    }

    private static String parseAddress(JsonElement elem) {
        if (elem.isJsonPrimitive()) return elem.getAsString();
        if (elem.isJsonObject() && elem.getAsJsonObject().has("value"))
            return String.format("0x%X", elem.getAsJsonObject().get("value").getAsLong());
        return elem.toString();
    }

    private static String str(JsonObject obj, String key) {
        return (obj.has(key) && obj.get(key).isJsonPrimitive()) ? obj.get(key).getAsString() : "";
    }
}
