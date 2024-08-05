/**
 * Parses rules data for the CapaTreeTable component
 * @param {Object} rules - The rules object from the rodc JSON data
 * @param {string} flavor - The flavor of the analysis (static or dynamic)
 * @param {Object} layout - The layout object from the rdoc JSON data
 * @param {number} [maxMatches=500] - Maximum number of matches to parse per rule
 * @returns {Array} - Parsed tree data for the TreeTable component
 */
export function parseRules(rules, flavor, layout, maxMatches = 1) {
    return Object.entries(rules).map(([, rule], index) => {
        const ruleNode = {
            key: `${index}`,
            data: {
                type: "rule",
                name: rule.meta.name,
                lib: rule.meta.lib,
                matchCount: rule.matches.length,
                namespace: rule.meta.namespace,
                mbc: rule.meta.mbc,
                source: rule.source,
                tactic: JSON.stringify(rule.meta.attack),
                attack: rule.meta.attack
                    ? rule.meta.attack.map((attack) => ({
                          tactic: attack.tactic,
                          technique: attack.technique,
                          id: attack.id.includes(".") ? attack.id.split(".")[0] : attack.id,
                          techniques: attack.subtechnique ? [{ technique: attack.subtechnique, id: attack.id }] : []
                      }))
                    : null
            }
        };

        // Is this a static rule with a file-level scope?
        const isFileScope = rule.meta.scopes && rule.meta.scopes.static === "file";

        // Limit the number of matches to process
        // Dynamic matches can have thousands of matches, only show `maxMatches` for performance reasons
        const limitedMatches = flavor === "dynamic" ? rule.matches.slice(0, maxMatches) : rule.matches;

        if (isFileScope) {
            // The scope for the rule is a file, so we don't need to show the match location address
            ruleNode.children = limitedMatches.map((match, matchIndex) => {
                return parseNode(match[1], `${index}-${matchIndex}`, rules, rule.meta.lib, layout);
            });
        } else {
            // This is not a file-level match scope, we need to create intermediate nodes for each match
            ruleNode.children = limitedMatches.map((match, matchIndex) => {
                const matchKey = `${index}-${matchIndex}`;
                const matchNode = {
                    key: matchKey,
                    data: {
                        type: "match location",
                        name:
                            flavor === "static"
                                ? `${rule.meta.scopes.static} @ ` + formatAddress(match[0])
                                : getProcessName(layout, match[0])
                    },
                    children: [parseNode(match[1], `${matchKey}`, rules, rule.meta.lib, layout)]
                };
                return matchNode;
            });
        }

        // Add a note if there are more matches than the limit
        if (rule.matches.length > limitedMatches.length) {
            ruleNode.children.push({
                key: `${index}`,
                data: {
                    type: "match location",
                    name: `... and ${rule.matches.length - maxMatches} more matches`
                }
            });
        }

        return ruleNode;
    });
}

/**
 * Parses rules data for the CapasByFunction component
 * @param {Object} data - The full JSON data object containing analysis results
 * @param {boolean} showLibraryRules - Whether to include library rules in the output
 * @returns {Array} - Parsed data for the CapasByFunction DataTable component
 */
export function parseFunctionCapabilities(data, showLibraryRules) {
    const result = [];
    const matchesByFunction = new Map();

    // Create a map of basic blocks to functions
    const functionsByBB = new Map();
    for (const func of data.meta.analysis.layout.functions) {
        const funcAddress = func.address.value;
        for (const bb of func.matched_basic_blocks) {
            functionsByBB.set(bb.address.value, funcAddress);
        }
    }

    // Iterate through all rules in the data
    for (const ruleId in data.rules) {
        const rule = data.rules[ruleId];

        // Skip library rules if showLibraryRules is false
        if (!showLibraryRules && rule.meta.lib) {
            continue;
        }

        if (rule.meta.scopes.static === "function") {
            // Function scope
            for (const [addr] of rule.matches) {
                const funcAddr = addr.value;
                if (!matchesByFunction.has(funcAddr)) {
                    matchesByFunction.set(funcAddr, new Map());
                }
                const funcMatches = matchesByFunction.get(funcAddr);
                funcMatches.set(rule.meta.name, {
                    count: (funcMatches.get(rule.meta.name)?.count || 0) + 1,
                    namespace: rule.meta.namespace,
                    lib: rule.meta.lib
                });
            }
        } else if (rule.meta.scopes.static === "basic block") {
            // Basic block scope
            for (const [addr] of rule.matches) {
                const bbAddr = addr.value;
                const funcAddr = functionsByBB.get(bbAddr);
                if (funcAddr) {
                    if (!matchesByFunction.has(funcAddr)) {
                        matchesByFunction.set(funcAddr, new Map());
                    }
                    const funcMatches = matchesByFunction.get(funcAddr);
                    funcMatches.set(rule.meta.name, {
                        count: (funcMatches.get(rule.meta.name)?.count || 0) + 1,
                        namespace: rule.meta.namespace,
                        lib: rule.meta.lib
                    });
                }
            }
        }
    }

    // Convert the matchesByFunction map to the intermediate result array
    for (const [funcAddr, matches] of matchesByFunction) {
        const functionAddress = funcAddr.toString(16).toUpperCase();
        const matchingRules = Array.from(matches, ([ruleName, data]) => ({
            ruleName,
            matchCount: data.count,
            namespace: data.namespace,
            lib: data.lib
        }));

        result.push({
            funcaddr: `0x${functionAddress}`,
            matchCount: matchingRules.length,
            capabilities: matchingRules,
            lib: data.lib
        });
    }

    // Transform the intermediate result into the final format
    const finalResult = result.flatMap((func) =>
        func.capabilities.map((cap) => ({
            funcaddr: func.funcaddr,
            matchCount: func.matchCount,
            ruleName: cap.ruleName,
            ruleMatchCount: cap.matchCount,
            namespace: cap.namespace,
            lib: cap.lib
        }))
    );

    return finalResult;
}

// Helper functions

/**
 * Parses a single `node` object (i.e. statement or feature) in each rule
 * @param {Object} node - The node to parse
 * @param {string} key - The key for this node
 * @param {Object} rules - The full rules object
 * @param {boolean} lib - Whether this is a library rule
 * @returns {Object} - Parsed node data
 */
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
            type: processedNode.node.type, // statement or feature
            typeValue: processedNode.node.statement
                ? processedNode.node.statement.type
                : processedNode.node.feature.type, // type value (eg. number, regex, api, or, and, optional ... etc)
            success: processedNode.success,
            name: getNodeName(processedNode),
            lib: lib,
            address: getNodeAddress(processedNode),
            description: getNodeDescription(processedNode),
            namespace: null,
            matchCount: null,
            source: null
        },
        children: []
    };
    // Recursively parse children
    if (processedNode.children && Array.isArray(processedNode.children)) {
        result.children = processedNode.children
            .map((child) => {
                const childNode = parseNode(child, `${key}`, rules, lib, layout);
                return childNode;
            })
            .filter((child) => child !== null);
    }
    // If this is a match node, add the rule's source code to the result.data.source object
    if (processedNode.node.feature && processedNode.node.feature.type === "match") {
        const ruleName = processedNode.node.feature.match;
        const rule = rules[ruleName];
        if (rule) {
            result.data.source = rule.source;
        }
        result.children = [];
    }
    // If this is an optional node, check if it has children. If not, return null (optional statement always evaluate to true)
    // we only render them, if they have at least one child node where node.success is true.
    if (processedNode.node.statement && processedNode.node.statement.type === "optional") {
        if (result.children.length === 0) return null;
    }

    if (processedNode.node.feature && processedNode.node.feature.type === "regex") {
        result.children = processRegexCaptures(processedNode, key);
    }

    // Add call information for dynamic sandbox traces
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

// TODO(s-ff): decide if we want to show call info or not
// e.g. explorer.exe{id:0,tid:10,pid:100,ppid:1000}
function getCallInfo(node, layout) {
    if (!node.locations || node.locations.length === 0) return null;

    const location = node.locations[0];
    if (location.type !== "call") return null;

    // eslint-disable-next-line no-unused-vars
    const [ppid, pid, tid, callId] = location.value;
    // eslint-disable-next-line no-unused-vars
    const callName = node.node.feature.api;

    const pname = getProcessName(layout, location);
    const cname = getCallName(layout, location);
    // eslint-disable-next-line no-unused-vars
    const [fname, separator, restWithArgs] = partition(cname, "(");
    const [args, , returnValueWithParen] = rpartition(restWithArgs, ")");

    const s = [];
    s.push(`${fname}(`);
    for (const arg of args.split(", ")) {
        s.push(`  ${arg},`);
    }
    s.push(`)${returnValueWithParen}`);

    //const callInfo = `${pname}{pid:${pid},tid:${tid},call:${callId}}\n${s.join('\n')}`;

    return { processName: pname, callInfo: s.join("\n") };
}

/**
 * Splits a string into three parts based on the first occurrence of a separator.
 * This function mimics Python's str.partition() method.
 *
 * @param {string} str - The input string to be partitioned.
 * @param {string} separator - The separator to use for partitioning.
 * @returns {Array<string>} An array containing three elements:
 *   1. The part of the string before the separator.
 *   2. The separator itself.
 *   3. The part of the string after the separator.
 *   If the separator is not found, returns [str, '', ''].
 *
 * @example
 * // Returns ["hello", ",", "world"]
 * partition("hello,world", ",");
 *
 * @example
 * // Returns ["hello world", "", ""]
 * partition("hello world", ":");
 */
function partition(str, separator) {
    const index = str.indexOf(separator);
    if (index === -1) {
        // Separator not found, return original string and two empty strings
        return [str, "", ""];
    }
    return [str.slice(0, index), separator, str.slice(index + separator.length)];
}

/**
 * Get the process name from the layout
 * @param {Object} layout - The layout object
 * @param {Object} address - The address object containing process information
 * @returns {string} The process name
 */
function getProcessName(layout, address) {
    if (!layout || !layout.processes || !Array.isArray(layout.processes)) {
        console.error("Invalid layout structure");
        return "Unknown Process";
    }

    const [ppid, pid] = address.value;

    for (const process of layout.processes) {
        if (
            process.address &&
            process.address.type === "process" &&
            process.address.value &&
            process.address.value[0] === ppid &&
            process.address.value[1] === pid
        ) {
            return process.name || "Unnamed Process";
        }
    }

    return "Unknown Process";
}

/**
 * Splits a string into three parts based on the last occurrence of a separator.
 * This function mimics Python's str.rpartition() method.
 *
 * @param {string} str - The input string to be partitioned.
 * @param {string} separator - The separator to use for partitioning.
 * @returns {Array<string>} An array containing three elements:
 *   1. The part of the string before the last occurrence of the separator.
 *   2. The separator itself.
 *   3. The part of the string after the last occurrence of the separator.
 *   If the separator is not found, returns ['', '', str].
 *
 * @example
 * // Returns ["hello,", ",", "world"]
 * rpartition("hello,world,", ",");
 *
 * @example
 * // Returns ["", "", "hello world"]
 * rpartition("hello world", ":");
 */
function rpartition(str, separator) {
    const index = str.lastIndexOf(separator);
    if (index === -1) {
        // Separator not found, return two empty strings and the original string
        return ["", "", str];
    }
    return [
        str.slice(0, index), // Part before the last separator
        separator, // The separator itself
        str.slice(index + separator.length) // Part after the last separator
    ];
}

/**
 * Get the call name from the layout
 * @param {Object} layout - The layout object
 * @param {Object} address - The address object containing call information
 * @returns {string} The call name with arguments
 */
function getCallName(layout, address) {
    if (!layout || !layout.processes || !Array.isArray(layout.processes)) {
        console.error("Invalid layout structure");
        return "Unknown Call";
    }

    const [ppid, pid, tid, callId] = address.value;

    for (const process of layout.processes) {
        if (
            process.address &&
            process.address.type === "process" &&
            process.address.value &&
            process.address.value[0] === ppid &&
            process.address.value[1] === pid
        ) {
            for (const thread of process.matched_threads) {
                if (
                    thread.address &&
                    thread.address.type === "thread" &&
                    thread.address.value &&
                    thread.address.value[2] === tid
                ) {
                    for (const call of thread.matched_calls) {
                        if (
                            call.address &&
                            call.address.type === "call" &&
                            call.address.value &&
                            call.address.value[3] === callId
                        ) {
                            return call.name || "Unnamed Call";
                        }
                    }
                }
            }
        }
    }

    return "Unknown Call";
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
        case "dn_token":
            return `token(${formatHex(address.value)})`;
        case "dn_token_offset": {
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
