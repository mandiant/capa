package capa.ghidra;

/**
 * Data held by each node in the Capa tree table.
 *
 * Columns:
 *   0 - Rule Information  (name / description of this node)
 *   1 - Address           (hex address string, if applicable)
 *   2 - Details           (namespace for capability nodes, details for match nodes)
 */
public class CapaNodeData {

    /** Type of node — drives rendering and navigation behaviour. */
    public enum NodeType {
        ROOT,
        CAPABILITY,   // top-level matched rule
        MATCH,        // address-level match under a capability
        INFO,         // informational / placeholder
        ERROR
    }

    private final NodeType nodeType;
    private final String   name;
    private final String   address;
    private final String   details;

    public CapaNodeData(NodeType nodeType, String name, String address, String details) {
        this.nodeType = nodeType;
        this.name     = name     != null ? name    : "";
        this.address  = address  != null ? address : "";
        this.details  = details  != null ? details : "";
    }

    // Convenience constructors
    public static CapaNodeData capability(String name, String namespace) {
        return new CapaNodeData(NodeType.CAPABILITY, name, "", namespace);
    }

    public static CapaNodeData match(String address, String function) {
        return new CapaNodeData(NodeType.MATCH, function != null ? function : "", address, "");
    }

    public static CapaNodeData info(String message) {
        return new CapaNodeData(NodeType.INFO, message, "", "");
    }

    public static CapaNodeData error(String message) {
        return new CapaNodeData(NodeType.ERROR, message, "", "");
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    public NodeType getNodeType() { return nodeType; }
    public String   getName()     { return name;     }
    public String   getAddress()  { return address;  }
    public String   getDetails()  { return details;  }

    /** Used by the tree column renderer to display the node label. */
    @Override
    public String toString() {
        return name;
    }
}