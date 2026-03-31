package capa.ghidra;

/**
 * CapaNodeData holds the three column values for a single row in the capa JTreeTable.
 *
 *  Column 0 – Rule Information  (shown in the tree column)
 *  Column 1 – Address           (hex address or empty)
 *  Column 2 – Details           (namespace / call detail / operand)
 */
public class CapaNodeData {

    public enum NodeType {
        RULE,          // top-level rule row  e.g. "create HTTP request (2 matches)"
        FUNCTION,      // function-scope match "function(sub_401880)"
        BASIC_BLOCK,   // basic block scope   "basic block @ 0x…"
        STATEMENT,     // and / or / optional / not
        FEATURE        // leaf feature        api(...) / string(...) / number(...) / regex(...)
    }

    private final String label;    // displayed in col-0 tree
    private final String address;  // col-1
    private final String details;  // col-2
    private final NodeType type;

    public CapaNodeData(String label, String address, String details, NodeType type) {
        this.label   = label   != null ? label   : "";
        this.address = address != null ? address : "";
        this.details = details != null ? details : "";
        this.type    = type;
    }

    /** Convenience constructor when type is not critical (statements/features). */
    public CapaNodeData(String label, String address, String details) {
        this(label, address, details, NodeType.FEATURE);
    }

    public String getLabel()   { return label;   }
    public String getAddress() { return address; }
    public String getDetails() { return details; }
    public NodeType getNodeType() { return type; }

    @Override
    public String toString() { return label; }
}