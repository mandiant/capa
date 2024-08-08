import { describe, it, expect } from "vitest";
import { parseRules, parseFunctionCapabilities } from "../utils/rdocParser";

describe("parseRules", () => {
    it("should return an empty array for empty rules", () => {
        const rules = {};
        const flavor = "static";
        const layout = {};
        const result = parseRules(rules, flavor, layout);
        expect(result).toEqual([]);
    });

    it("should correctly parse a simple rule with static scope", () => {
        const rules = {
            "test rule": {
                meta: {
                    name: "test rule",
                    namespace: "test",
                    lib: false,
                    scopes: {
                        static: "function",
                        dynamic: "process"
                    }
                },
                source: "test rule source",
                matches: [
                    [
                        { type: "absolute", value: 0x1000 },
                        {
                            success: true,
                            node: { type: "feature", feature: { type: "api", api: "TestAPI" } },
                            children: [],
                            locations: [{ type: "absolute", value: 0x1000 }],
                            captures: {}
                        }
                    ]
                ]
            }
        };
        const result = parseRules(rules, "static", {});
        expect(result).toHaveLength(1);
        expect(result[0].key).toBe("0");
        expect(result[0].data.type).toBe("rule");
        expect(result[0].data.name).toBe("test rule");
        expect(result[0].data.lib).toBe(false);
        expect(result[0].data.namespace).toBe("test");
        expect(result[0].data.source).toBe("test rule source");
        expect(result[0].children).toHaveLength(1);
        expect(result[0].children[0].key).toBe("0-0");
        expect(result[0].children[0].data.type).toBe("match location");
        expect(result[0].children[0].children[0].data.type).toBe("feature");
        expect(result[0].children[0].children[0].data.typeValue).toBe("api");
        expect(result[0].children[0].children[0].data.name).toBe("TestAPI");
    });

    it('should handle rule with "not" statements correctly', () => {
        const rules = {
            "test rule": {
                meta: {
                    name: "test rule",
                    namespace: "test",
                    lib: false,
                    scopes: {
                        static: "function",
                        dynamic: "process"
                    }
                },
                source: "test rule source",
                matches: [
                    [
                        { type: "absolute", value: 0x1000 },
                        {
                            success: true,
                            node: { type: "statement", statement: { type: "not" } },
                            children: [
                                { success: false, node: { type: "feature", feature: { type: "api", api: "TestAPI" } } }
                            ]
                        }
                    ]
                ]
            }
        };
        const result = parseRules(rules, "static", {});
        expect(result).toHaveLength(1);
        expect(result[0].children[0].children[0].data.type).toBe("statement");
        expect(result[0].children[0].children[0].data.name).toBe("not:");
        expect(result[0].children[0].children[0].children[0].data.type).toBe("feature");
        expect(result[0].children[0].children[0].children[0].data.typeValue).toBe("api");
        expect(result[0].children[0].children[0].children[0].data.name).toBe("TestAPI");
    });
});

describe("parseFunctionCapabilities", () => {
    it("should return an empty array when no functions match", () => {
        const mockData = {
            meta: {
                analysis: {
                    feature_counts: {
                        file: 0,
                        functions: []
                    },
                    layout: {
                        functions: []
                    }
                }
            },
            rules: {}
        };
        const result = parseFunctionCapabilities(mockData, false);
        expect(result).toEqual([]);
    });

    it("should parse a single function with one rule match", () => {
        const mockDoc = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { type: "absolute", value: 0x1000 },
                                matched_basic_blocks: [{ address: { type: "absolute", value: 0x1000 } }]
                            }
                        ]
                    },
                    feature_counts: {
                        functions: [{ address: { type: "absolute", value: 0x1000 } }]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Test Rule",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ type: "absolute", value: 0x1000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockDoc);
        expect(result).toEqual([
            {
                address: "0x1000",
                capabilities: [{ name: "Test Rule", namespace: "test", lib: false }]
            }
        ]);
    });

    it("should handle multiple rules matching a single function", () => {
        const mockDoc = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { type: "absolute", value: 0x1000 },
                                matched_basic_blocks: [{ address: { type: "absolute", value: 0x1000 } }]
                            }
                        ]
                    },
                    feature_counts: {
                        functions: [{ address: { type: "absolute", value: 0x1000 } }]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Test Rule 1",
                        lib: true,
                        scopes: { static: "function" }
                    },
                    matches: [[{ type: "absolute", value: 0x1000 }]]
                },
                rule2: {
                    meta: {
                        name: "Test Rule 2",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ type: "absolute", value: 0x1000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockDoc);
        expect(result).toEqual([
            {
                address: "0x1000",
                capabilities: [
                    { name: "Test Rule 1", lib: true },
                    { name: "Test Rule 2", namespace: "test", lib: false }
                ]
            }
        ]);
    });

    it("should handle basic block scoped rules", () => {
        const mockDoc = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { type: "absolute", value: 0x1000 },
                                matched_basic_blocks: [{ address: { type: "absolute", value: 0x1100 } }]
                            }
                        ]
                    },
                    feature_counts: {
                        functions: [{ address: { type: "absolute", value: 0x1000 } }]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Basic Block Rule",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "basic block" }
                    },
                    matches: [[{ type: "absolute", value: 0x1100 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockDoc);
        expect(result).toEqual([
            {
                address: "0x1000",
                capabilities: [{ name: "Basic Block Rule", namespace: "test", lib: false }]
            }
        ]);
    });

    it("should handle a single rule matching in multiple functions", () => {
        const mockDoc = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { type: "absolute", value: 0x1000 },
                                matched_basic_blocks: [{ address: { type: "absolute", value: 0x1000 } }]
                            },
                            {
                                address: { type: "absolute", value: 0x2000 },
                                matched_basic_blocks: [{ address: { type: "absolute", value: 0x2000 } }]
                            }
                        ]
                    },
                    feature_counts: {
                        functions: [
                            { address: { type: "absolute", value: 0x1000 } },
                            { address: { type: "absolute", value: 0x2000 } }
                        ]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Test Rule",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ type: "absolute", value: 0x1000 }], [{ type: "absolute", value: 0x2000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockDoc);
        expect(result).toEqual([
            {
                address: "0x1000",
                capabilities: [{ name: "Test Rule", namespace: "test", lib: false }]
            },
            {
                address: "0x2000",
                capabilities: [{ name: "Test Rule", namespace: "test", lib: false }]
            }
        ]);
    });
});
