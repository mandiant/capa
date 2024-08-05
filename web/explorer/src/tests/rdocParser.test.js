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
        const mockData = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: {
                                    type: "absolute",
                                    value: 0x1000
                                },
                                matched_basic_blocks: [
                                    {
                                        address: {
                                            type: "absolute",
                                            value: 0x1000
                                        }
                                    }
                                ]
                            }
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
                    matches: [[{ value: 0x1000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockData, false);
        expect(result).toHaveLength(1);
        expect(result[0]).toEqual({
            funcaddr: "0x1000",
            matchCount: 1,
            ruleName: "Test Rule",
            ruleMatchCount: 1,
            namespace: "test",
            lib: false
        });
    });

    it("should handle multiple rules matching a single function", () => {
        const mockData = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: {
                                    type: "absolute",
                                    value: 0x1000
                                },
                                matched_basic_blocks: []
                            }
                        ]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Rule 1",
                        namespace: "test1",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ value: 0x1000 }]]
                },
                rule2: {
                    meta: {
                        name: "Rule 2",
                        namespace: "test2",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ value: 0x1000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockData, false);
        expect(result).toHaveLength(2);
        expect(result[0].funcaddr).toBe("0x1000");
        expect(result[1].funcaddr).toBe("0x1000");
        expect(result.map((r) => r.ruleName)).toEqual(["Rule 1", "Rule 2"]);
    });

    it("should handle library rules correctly", () => {
        const mockData = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { type: "absolute", value: 0x1000 },
                                matched_basic_blocks: []
                            }
                        ]
                    }
                }
            },
            rules: {
                libRule: {
                    meta: {
                        name: "Lib Rule",
                        namespace: "lib",
                        lib: true,
                        scopes: { static: "function" }
                    },
                    matches: [[{ value: 0x1000 }]]
                }
            }
        };
        const resultWithLib = parseFunctionCapabilities(mockData, true);
        expect(resultWithLib).toHaveLength(1);
        expect(resultWithLib[0].lib).toBe(true);

        const resultWithoutLib = parseFunctionCapabilities(mockData, false);
        expect(resultWithoutLib).toHaveLength(0);
    });

    it("should handle a single rule matching in multiple functions", () => {
        const mockData = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            { address: { value: 0x1000 }, matched_basic_blocks: [] },
                            { address: { value: 0x2000 }, matched_basic_blocks: [] }
                        ]
                    }
                }
            },
            rules: {
                rule1: {
                    meta: {
                        name: "Multi-function Rule",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "function" }
                    },
                    matches: [[{ value: 0x1000 }], [{ value: 0x2000 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockData, false);
        expect(result).toHaveLength(2);
        expect(result[0].funcaddr).toBe("0x1000");
        expect(result[0].ruleName).toBe("Multi-function Rule");
        expect(result[0].ruleMatchCount).toBe(1);
        expect(result[1].funcaddr).toBe("0x2000");
        expect(result[1].ruleName).toBe("Multi-function Rule");
        expect(result[1].ruleMatchCount).toBe(1);
    });

    it("should handle basic block scoped rules", () => {
        const mockData = {
            meta: {
                analysis: {
                    layout: {
                        functions: [
                            {
                                address: { value: 0x1000 },
                                matched_basic_blocks: [{ address: { value: 0x1010 } }]
                            }
                        ]
                    }
                }
            },
            rules: {
                bbRule: {
                    meta: {
                        name: "Basic Block Rule",
                        namespace: "test",
                        lib: false,
                        scopes: { static: "basic block" }
                    },
                    matches: [[{ value: 0x1010 }]]
                }
            }
        };
        const result = parseFunctionCapabilities(mockData, false);
        expect(result).toHaveLength(1);
        expect(result[0].funcaddr).toBe("0x1000");
        expect(result[0].ruleName).toBe("Basic Block Rule");
    });
});
