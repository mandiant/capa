/**
 * Parses rules data for the CapaTreeTable component
 * @param {Object} rules - The rules object from the rodc JSON data
 * @param {string} flavor - The flavor of the analysis (static or dynamic)
 * @param {Object} layout - The layout object from the rdoc JSON data
 * @param {number} [maxMatches=300] - Maximum number of matches to parse per rule (used for optimized rendering in dynamic analysis)
 * @returns {Array} - Parsed tree data for the TreeTable component
 */
export function parseRules(rules, flavor, _layout, maxMatches = 300) {
    const layout = preprocessLayout(_layout);
    const treeData = [];
    let index = 0;

    for (const [, rule] of Object.entries(rules)) {
        const ruleNode = createRuleNode(rule, index, flavor);

        // Limit the number of matches to process
        // Dynamic matches can have thousands of matches, only show `maxMatches` for rendering optimization
        const matchesToProcess = flavor === "dynamic" ? rule.matches.slice(0, maxMatches) : rule.matches;

        for (let matchIndex = 0; matchIndex < matchesToProcess.length; matchIndex++) {
            const match = matchesToProcess[matchIndex];
            const matchKey = `${index}-${matchIndex}`;

            // Check if the rule has a file-level scope
            if (rule.meta.scopes && rule.meta.scopes.static === "file") {
                // The scope for the rule is a file, so we don't need to show the match location address
                ruleNode.children.push(parseNode(match[1], matchKey, rules, rule.meta.lib, layout));
            } else {
                // This is not a file-level match scope, we need to create an intermediate node for each match
                const matchNode = createMatchNode(rule.meta.scopes.static, match, matchKey, flavor, layout);
                matchNode.children.push(parseNode(match[1], matchKey, rules, rule.meta.lib, layout));
                ruleNode.children.push(matchNode);
            }
        }

        // Add note for additional non-covered matches in dynamic mode
        if (flavor === "dynamic" && rule.matches.length > maxMatches) {
            ruleNode.children.push(createAdditionalMatchesNode(index, rule.matches.length - maxMatches));
        }

        treeData.push(ruleNode);
        index++;
    }
    return treeData;
}

/**
 * Preprocesses the layout to create efficient lookup maps
 * @param {Object} layout - The layout object from rdoc JSON data
 * @returns {Object} An object containing lookup maps for calls, threads, and processes
 */
function preprocessLayout(layout) {
    const processMap = new Map();
    const threadMap = new Map();
    const callMap = new Map();

    if (layout && layout.processes) {
        for (const process of layout.processes) {
            if (process.address && process.address.type === "process" && process.address.value) {
                const [ppid, pid] = process.address.value;
                processMap.set(`${ppid}-${pid}`, process);

                if (process.matched_threads) {
                    for (const thread of process.matched_threads) {
                        if (thread.address && thread.address.type === "thread" && thread.address.value) {
                            const [, , tid] = thread.address.value;
                            threadMap.set(`${ppid}-${pid}-${tid}`, thread);

                            if (thread.matched_calls) {
                                for (const call of thread.matched_calls) {
                                    if (call.address && call.address.type === "call" && call.address.value) {
                                        const [, , , callId] = call.address.value;
                                        callMap.set(`${ppid}-${pid}-${tid}-${callId}`, call);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return { processMap, threadMap, callMap };
}
// Creates a node for a rule
function createRuleNode(rule, index) {
    return {
        key: `${index}`,
        data: {
            type: "rule",
            name: rule.meta.name,
            lib: rule.meta.lib,
            matchCount: rule.matches.length,
            namespace: rule.meta.namespace,
            mbc: rule.meta.mbc,
            source: rule.source,
            attack: rule.meta.attack
        },
        children: []
    };
}

// Creates a match location (e.g. basic block @ 0x1000 or explorer.exe (ppid: 1234, pid: 5678)) node
function createMatchNode(scope, match, matchKey, flavor, layout) {
    const [location] = match;
    const name = flavor === "static" ? `${scope} @ ${formatAddress(location)}` : getProcessName(layout, location);

    return {
        key: matchKey,
        data: {
            type: "match location",
            name: name
        },
        children: []
    };
}

// Creates a note node for additional non-covered matches in dynamic mode
function createAdditionalMatchesNode(index, additionalMatchCount) {
    return {
        key: `${index}`,
        data: {
            type: "match location",
            name: `... and ${additionalMatchCount} more matches`
        }
    };
}

/**
 * Parses a single `node` object (i.e. statement or feature) in each rule
 * @param {Object} node - The node to parse
 * @param {string} key - The key for this node
 * @param {Object} rules - The full rules object
 * @param {boolean} lib - Whether this is a library rule
 * @returns {Object} - Parsed node data
 **/

function parseNode(node, key, rules, lib, layout) {
    if (!node) return null;

    const isNotStatement = node.node.statement && node.node.statement.type === "not";
    const processedNode = isNotStatement ? invertNotStatementSuccess(node) : node;

    if (!processedNode.success) {
        return null;
    }

    const result = {
        key: key,
        data: {
            type: processedNode.node.type, // feature or statement
            typeValue: processedNode.node.statement?.type || processedNode.node.feature?.type,
            success: processedNode.success,
            name: getNodeName(processedNode),
            lib: lib,
            address: getNodeAddress(processedNode),
            description: getNodeDescription(processedNode)
        },
        children: []
    };

    if (processedNode.children && Array.isArray(processedNode.children)) {
        result.children = processedNode.children
            .map((child) => parseNode(child, `${key}`, rules, lib, layout))
            .filter((child) => child !== null);
    }

    if (processedNode.node.feature && processedNode.node.feature.type === "match") {
        const ruleName = processedNode.node.feature.match;
        const rule = rules[ruleName];
        if (rule) {
            result.data.source = rule.source;
        }
        result.children = [];
    }

    if (
        processedNode.node.statement &&
        processedNode.node.statement.type === "optional" &&
        result.children.length === 0
    ) {
        return null;
    }

    if (processedNode.node.feature && processedNode.node.feature.type === "regex") {
        result.children = processRegexCaptures(processedNode, key);
    }

    if (processedNode.node.feature && processedNode.node.feature.type === "api") {
        const callInfo = getCallInfo(node, layout);
        if (callInfo) {
            result.children.push({
                key: key,
                data: {
                    type: "call-info",
                    name: callInfo
                },
                children: []
            });
        }
    }

    return result;
}

/**
 * Get the process name using the optimized processNames Map
 * @param {Map} layout - The layout object containing maps
 * @param {Object} address - The address object containing process information
 * @returns {string} The process name
 */
function getProcessName(layout, address) {
    const [ppid, pid] = address.value;
    const processKey = `${ppid}-${pid}`;
    const process = layout.processMap.get(processKey);
    return process.name + ` (ppid:${ppid}, pid:${pid})`;
}

/**
 * Parses the capabilities of functions from a given rdoc.
 *
 * @param {Object} doc - The document containing function and rule information.
 * @returns {Array} An array of objects, each representing a function with its address and capabilities.
 *
 * @example
 * [
 *  {
 *    "address": "0x14002A690",
 *    "capabilities": [
 *      {
 *        "name": "contain loop",
 *        "lib": true
 *
 *      },
 *      {
 *        "name": "get disk information",
 *        "namespace": "host-interaction/hardware/storage"
 *        "lib": false
 *      }
 *    ]
 *   }
 * ]
 */
export function parseFunctionCapabilities(doc) {
    // Map basic blocks to their their parent functions
    const functionsByBB = new Map();

    for (const finfo of doc.meta.analysis.layout.functions) {
        const faddress = finfo.address;
        for (const bb of finfo.matched_basic_blocks) {
            const bbaddress = bb.address;
            functionsByBB.set(formatAddress(bbaddress), formatAddress(faddress));
        }
    }

    // Map to store capabilities matched to each function
    const matchesByFunction = new Map();

    // Add a special entry for file-level matches
    matchesByFunction.set("file", new Set());

    // Iterate through all rules in the document
    for (const [, rule] of Object.entries(doc.rules)) {
        if (rule.meta.scopes.static === "function") {
            for (const [address] of rule.matches) {
                const addr = formatAddress(address);
                if (!matchesByFunction.has(addr)) {
                    matchesByFunction.set(addr, new Set());
                }
                matchesByFunction
                    .get(addr)
                    .add({ name: rule.meta.name, namespace: rule.meta.namespace, lib: rule.meta.lib });
            }
        } else if (rule.meta.scopes.static === "basic block") {
            for (const [address] of rule.matches) {
                const addr = formatAddress(address);
                const function_ = functionsByBB.get(addr);
                if (function_) {
                    if (!matchesByFunction.has(function_)) {
                        matchesByFunction.set(function_, new Set());
                    }
                    matchesByFunction
                        .get(function_)
                        .add({ name: rule.meta.name, namespace: rule.meta.namespace, lib: rule.meta.lib });
                }
            }
        } else if (rule.meta.scopes.static === "file") {
            // Add file-level matches to the special 'file' entry
            matchesByFunction.get("file").add({
                name: rule.meta.name,
                namespace: rule.meta.namespace,
                lib: rule.meta.lib
            });
        }
    }

    const result = [];

    // Add file-level matches if there are any
    if (matchesByFunction.get("file").size > 0) {
        result.push({
            address: "file",
            capabilities: Array.from(matchesByFunction.get("file"))
        });
    }

    // Iterate through all functions in the document
    for (const f of doc.meta.analysis.feature_counts.functions) {
        const addr = formatAddress(f.address);
        const matches = matchesByFunction.get(addr);
        // Skip functions with no matches (unlikely)
        if (!matches || matches.size === 0) continue;

        // Add function to result with its address and sorted capabilities
        result.push({
            address: addr,
            capabilities: Array.from(matches)
        });
    }

    return result;
}

// Helper functions

function getCallInfo(node, layout) {
    if (!node.locations || node.locations.length === 0) return null;

    const location = node.locations[0];
    if (location.type !== "call") return null;

    const pname = getProcessName(layout, location);
    const cname = getCallName(layout, location);

    return { processName: pname, callInfo: cname };
}

/**
 * Get the call name from the preprocessed layout maps
 * @param {Object} layoutMaps - The preprocessed layout maps
 * @param {Object} address - The address object containing call information
 * @returns {string} The call name or "Unknown Call" if not found
 */
function getCallName(layoutMaps, address) {
    if (!address || !address.value || address.value.length < 4) {
        return "Unknown Call";
    }

    const [ppid, pid, tid, callId] = address.value;
    const callKey = `${ppid}-${pid}-${tid}-${callId}`;

    const call = layoutMaps.callMap.get(callKey);
    return call.name;
}

function processRegexCaptures(node, key) {
    if (!node.captures) return [];

    return Object.entries(node.captures).map(([capture, locations]) => ({
        key: key,
        data: {
            type: "regex-capture",
            name: `"${escape(capture)}"`,
            address: formatAddress(locations[0])
        }
    }));
}

function formatAddress(address) {
    switch (address.type) {
        case "absolute":
            return formatHex(address.value);
        case "relative":
            return `base address+${formatHex(address.value)}`;
        case "file":
            return `file+${formatHex(address.value)}`;
        case "dn token":
            return `token(${formatHex(address.value)})`;
        case "dn token offset": {
            const [token, offset] = address.value;
            return `token(${formatHex(token)})+${formatHex(offset)}`;
        }
        case "process":
            //const [ppid, pid] = address.value;
            //return `process{pid:${pid}}`;
            return formatDynamicAddress(address.value);
        case "thread":
            //const [threadPpid, threadPid, tid] = address.value;
            //return `process{pid:${threadPid},tid:${tid}}`;
            return formatDynamicAddress(address.value);
        case "call":
            //const [callPpid, callPid, callTid, id] = address.value;
            //return `process{pid:${callPid},tid:${callTid},call:${id}}`;
            return formatDynamicAddress(address.value);
        case "no address":
            return "";
        default:
            throw new Error("Unexpected address type");
    }
}

function escape(str) {
    return str.replace(/"/g, '\\"');
}

/**
 * Inverts the success values for children of a 'not' statement
 * @param {Object} node - The node to invert
 * @returns {Object} The inverted node
 */
function invertNotStatementSuccess(node) {
    if (!node) return null;

    return {
        ...node,
        children: node.children
            ? node.children.map((child) => ({
                  ...child,
                  success: !child.success,
                  children: child.children ? invertNotStatementSuccess(child).children : []
              }))
            : []
    };
}

/**
 * Gets the description of a node
 * @param {Object} node - The node to get the description from
 * @returns {string|null} The description or null if not found
 */
function getNodeDescription(node) {
    if (node.node.statement) {
        return node.node.statement.description;
    } else if (node.node.feature) {
        return node.node.feature.description;
    } else {
        return null;
    }
}

/**
 * Gets the name of a node
 * @param {Object} node - The node to get the name from
 * @returns {string} The name of the node
 */
function getNodeName(node) {
    if (node.node.statement) {
        return getStatementName(node.node.statement);
    } else if (node.node.feature) {
        return getFeatureName(node.node.feature);
    }
    return null;
}

/**
 * Gets the name for a statement node
 * @param {Object} statement - The statement object
 * @returns {string} The name of the statement
 */
function getStatementName(statement) {
    switch (statement.type) {
        case "subscope":
            // for example, "basic block: "
            return `${statement.scope}:`;
        case "range":
            return getRangeName(statement);
        case "some":
            return `${statement.count} or more`;
        default:
            // statement (e.g. "and: ", "or: ", "optional:", ... etc)
            return `${statement.type}:`;
    }
}

/**
 * Gets the name for a feature node
 * @param {Object} feature - The feature object
 * @returns {string} The name of the feature
 */
function getFeatureName(feature) {
    switch (feature.type) {
        case "number":
        case "offset":
            // example: "number: 0x1234", "offset: 0x3C"
            // return `${feature.type}: 0x${feature[feature.type].toString(16).toUpperCase()}`
            return `0x${feature[feature.type].toString(16).toUpperCase()}`;
        case "bytes":
            return formatBytes(feature.bytes);
        case "operand offset":
            return `operand[${feature.index}].offset: 0x${feature.operand_offset.toString(16).toUpperCase()}`;
        case "class":
            return `${feature.class_}`;
        default:
            return `${feature[feature.type]}`;
    }
}

/**
 * Formats the name for a range statement
 * @param {Object} statement - The range statement object
 * @returns {string} The formatted range name
 */
function getRangeName(statement) {
    const { child, min, max } = statement;
    const { type, [type]: value } = child;
    const rangeType = value || value === 0 ? `count(${type}(${value}))` : `count(${type})`;
    let rangeValue;

    if (min === max) {
        rangeValue = `${min}`;
    } else if (max >= Number.MAX_SAFE_INTEGER) {
        rangeValue = `${min} or more`;
    } else {
        rangeValue = `between ${min} and ${max}`;
    }

    // for example: count(mnemonic(xor)): 2 or more
    return `${rangeType}: ${rangeValue} `;
}

/**
 * Gets the address of a node
 * @param {Object} node - The node to get the address from
 * @returns {string|null} The formatted address or null if not found
 */
function getNodeAddress(node) {
    if (node.node.feature && node.node.feature.type === "regex") return null;
    if (node.locations && node.locations.length > 0) {
        return formatAddress(node.locations[0]);
    }
    return null;
}

/**
 * Formats bytes string for display
 * @param {Array} value - The bytes string
 * @returns {string} - Formatted bytes string
 */

function formatBytes(byteString) {
    // Use a regular expression to insert a space after every two characters
    const formattedString = byteString.replace(/(.{2})/g, "$1 ").trim();
    // convert to uppercase
    return formattedString.toUpperCase();
}

/**
 * Formats the address for dynamic flavor
 * @param {Array} value - The address value array
 * @returns {string} - Formatted address string
 */
function formatDynamicAddress(value) {
    const parts = ["ppid", "pid", "tid", "id"];
    return value
        .map((item, index) => `${parts[index]}:${item}`)
        .reverse()
        .join(",");
}

function formatHex(address) {
    return `0x${address.toString(16).toUpperCase()}`;
}
