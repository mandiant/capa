/**
 * Parses rules data for the CapaTreeTable component
 * @param {Object} rules - The rules object from the rodc JSON data
 * @returns {Array} - Parsed tree data for the TreeTable component
 */
export function parseRules(rules, flavor) {
  return Object.entries(rules).map(([ruleName, rule], index) => {
    const ruleNode = {
      key: index.toString(),
      data: {
        type: 'rule',
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
              id: attack.id.includes('.') ? attack.id.split('.')[0] : attack.id,
              techniques: attack.subtechnique
                ? [{ technique: attack.subtechnique, id: attack.id }]
                : []
            }))
          : null
      }
    }
    // Is this a static rule with a file-level scope?
    const isFileScope = rule.meta.scopes && rule.meta.scopes.static === 'file'

    if (isFileScope) {
      // The scope for the rule is a file, so we don't need to show the match location address
      ruleNode.children = rule.matches.map((match, matchIndex) => {
        return parseNode(match[1], `${index}-${matchIndex}`, rules, rule.meta.lib)
      })
    } else {
      // This is not a file-level match scope, we need to create intermediate nodes for each match
      // e.g. for a rule with a static scope of "function" we need to create a node for each function
      // like function @ 0x400010, function @ 0x400020, etc.
      let matchCounter = 0
      ruleNode.children = rule.matches.map((match) => {
        const matchKey = `${index}-${matchCounter}`
        const matchNode = {
          key: matchKey,
          data: {
            type: 'match location',
            name:
              flavor === 'static'
                ? `${rule.meta.scopes.static} @ ${formatStaticAddress(match[0].value)}`
                : `${formatDynamicAddress(match[0].value)}`,
            address:
              flavor === 'static'
                ? `${formatStaticAddress(match[0].value)}`
                : formatDynamicAddress(match[0].value),
          },
          children: [parseNode(match[1], `${matchKey}-0`, rules, rule.meta.lib)]
        }
        matchCounter++
        return matchNode
      })
    }

    return ruleNode
  })
}

/**
 * Parses rules data for the CapasByFunction component
 * @param {Object} data - The full JSON data object containing analysis results
 * @param {boolean} showLibraryRules - Whether to include library rules in the output
 * @returns {Array} - Parsed data for the CapasByFunction DataTable component
 */
export function parseFunctionCapabilities(data, showLibraryRules) {
  const result = [];
  let id = 0;

  // Iterate through each function in the metadata
  for (const functionInfo of data.meta.analysis.layout.functions) {
    // Convert function address to uppercase hexadecimal string
    const functionAddress = functionInfo.address.value.toString(16).toUpperCase();
    const matchingRules = [];

    // Iterate through all rules in the data
    for (const ruleId in data.rules) {
      const rule = data.rules[ruleId];

      // Skip library rules if showLibraryRules is false
      if (!showLibraryRules && rule.meta.lib) {
        continue;
      }

      // Find matches for this rule within the current function
      const matches = rule.matches.filter((match) =>
        // Check if any of the function's basic blocks match the rule
        functionInfo.matched_basic_blocks.some((block) => block.address.value === match[0].value)
      );

      // If there are matches, add this rule to the matchingRules array
      if (matches.length > 0) {
        matchingRules.push({
          ruleName: rule.meta.name,
          lib: rule.meta.lib,
          namespace: rule.meta.namespace,
          source: rule.source
        });
      }
    }

    // If there are matching rules for this function, add it to the result
    if (matchingRules.length > 0) {
      // Add each matching rule as a separate row
      matchingRules.forEach(rule => {
        result.push({
          id: id++,
          funcaddr: `0x${functionAddress}`,
          matchcount: matchingRules.length,
          ...rule
        });
      });
    }
  }

  return result;
}

/**
 * Parses rules data for the CapasByProcess component
 * @param {Object} data - The full JSON data object containing analysis results
 * @param {boolean} showLibraryRules - Whether to include library rules in the output
 * @returns {Array} - Parsed tree data for the CapasByProcess component
 */
export function parseProcessCapabilities(data, showLibraryRules) {
  const result = []
  const processes = data.meta.analysis.layout.processes

  let processKey = 1

  // Iterate through each process in the rdoc
  for (const processInfo of processes) {
    const processName = processInfo.name
    const matchingRules = []

    // Iterate through all rules in the data
    for (const ruleId in data.rules) {
      const rule = data.rules[ruleId]

      // Skip library rules if showLibraryRules is false
      if (!showLibraryRules && rule.meta.lib) {
        continue
      }

      // Check if the rule's scope is 'process'
      if (rule.meta.scopes.dynamic === 'process') {
        // Find matches for this rule within the current process
        const matches = rule.matches.filter(
          (match) =>
            match[0].type === 'process' &&
            // Ensure all addresses in the match are included in the process's address
            match[0].value.every((addr) => processInfo.address.value.includes(addr))
        )

        // If there are matches, add this rule to the matchingRules array
        if (matches.length > 0) {
          matchingRules.push({
            key: `${processName}-${matchingRules.length}`, // Unique key for each rule
            data: {
              processname: `rule: ${rule.meta.name}`, // Display rule name
              type: 'rule',
              matchcount: null, // Matchcount is not relevant here
              namespace: rule.meta.namespace,
              procID: processInfo.address.value.join(', '), // PID, PPID
              source: rule.source
            }
          })
        }
      }
    }

    // If there are matching rules for this process, add it to the result
    if (matchingRules.length > 0) {
      result.push({
        key: `process-${processKey++}`, // Unique key for each process
        data: {
          processname: processName, // Process name
          type: 'process',
          matchcount: matchingRules.length, // Number of matching rules for this process
          namespace: null, // Processes don't have a namespace
          procID: processInfo.address.value.join(', '), // PID, PPID
          source: null // Processes don't have source code in this context
        },
        children: matchingRules // Add matching rules as children
      })
    }
  }

  return result
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
function parseNode(node, key, rules, lib) {
  if (!node) return null

  const isNotStatement = node.node.statement && node.node.statement.type === 'not'
  const processedNode = isNotStatement ? invertNotStatementSuccess(node) : node

  if (!processedNode.success) {
    return null
  }

  let childCounter = 0

  const result = {
    key: key,
    data: {
      type: processedNode.node.type, // statement or feature
      typeValue: processedNode.node.statement ? processedNode.node.statement.type : processedNode.node.feature.type, // type value (eg. number, regex, api, or, and, optional ... etc)
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
  }
  // Recursively parse children
  if (processedNode.children && Array.isArray(processedNode.children)) {
    result.children = processedNode.children
      .map((child) => {
        const childNode = parseNode(child, `${key}-${childCounter}`, rules, lib)
        if (childNode) {
          childCounter++
        }
        return childNode
      })
      .filter((child) => child !== null)
  }
  // If this is a match node, add the rule's source code to the result.data.source object
  if (processedNode.node.feature && processedNode.node.feature.type === 'match') {
    const ruleName = processedNode.node.feature.match
    const rule = rules[ruleName]
    if (rule) {
      result.data.source = rule.source
    }
    result.children = []
  }
  // If this is an optional node, check if it has children. If not, return null (optional statement always evaluate to true)
  // we only render them, if they have at least one child node where node.success is true.
  if (processedNode.node.statement && processedNode.node.statement.type === 'optional') {
    if (result.children.length === 0) return null
  }

  return result
}

/**
 * Inverts the success values for children of a 'not' statement
 * @param {Object} node - The node to invert
 * @returns {Object} The inverted node
 */
function invertNotStatementSuccess(node) {
  if (!node) return null

  return {
    ...node,
    children: node.children
      ? node.children.map((child) => ({
          ...child,
          success: !child.success,
          children: child.children ? invertNotStatementSuccess(child).children : []
        }))
      : []
  }
}

/**
 * Gets the description of a node
 * @param {Object} node - The node to get the description from
 * @returns {string|null} The description or null if not found
 */
function getNodeDescription(node) {
  if (node.node.statement) {
    return node.node.statement.description
  } else if (node.node.feature) {
    return node.node.feature.description
  } else {
    return null
  }
}

/**
 * Gets the name of a node
 * @param {Object} node - The node to get the name from
 * @returns {string} The name of the node
 */
function getNodeName(node) {
  if (node.node.statement) {
    return getStatementName(node.node.statement)
  } else if (node.node.feature) {
    return getFeatureName(node.node.feature)
  }
  return null
}

/**
 * Gets the name for a statement node
 * @param {Object} statement - The statement object
 * @returns {string} The name of the statement
 */
function getStatementName(statement) {
  switch (statement.type) {
    case 'subscope':
      // for example, "basic block: "
      return `${statement.scope}:`
    case 'range':
      return getRangeName(statement)
    case 'some':
      return `${statement.count} or more`
    default:
      // statement (e.g. "and: ", "or: ", "optional:", ... etc)
      return `${statement.type}:`
  }
}

/**
 * Gets the name for a feature node
 * @param {Object} feature - The feature object
 * @returns {string} The name of the feature
 */
function getFeatureName(feature) {
  switch (feature.type) {
    case 'number':
    case 'offset':
      // example: "number: 0x1234", "offset: 0x3C"
      // return `${feature.type}: 0x${feature[feature.type].toString(16).toUpperCase()}`
      return `0x${feature[feature.type].toString(16).toUpperCase()}`
    case 'bytes':
      return formatBytes(feature.bytes)
    case 'operand offset':
      return `operand[${feature.index}].offset: 0x${feature.operand_offset.toString(16).toUpperCase()}`
    default:
      return `${feature[feature.type]}`
  }
}

/**
 * Formats the name for a range statement
 * @param {Object} statement - The range statement object
 * @returns {string} The formatted range name
 */
function getRangeName(statement) {
  const { child, min, max } = statement
  const { type, [type]: value } = child
  const rangeType = value || value === 0 ? `count(${type}(${value}))` : `count(${type})`
  let rangeValue

  if (min === max) {
    rangeValue = `${min}`
  } else if (max >= Number.MAX_SAFE_INTEGER) {
    rangeValue = `${min} or more`
  } else {
    rangeValue = `between ${min} and ${max}`
  }

  // for example: count(mnemonic(xor)): 2 or more
  return `${rangeType}: ${rangeValue} `
}

/**
 * Gets the address of a node
 * @param {Object} node - The node to get the address from
 * @returns {string|null} The formatted address or null if not found
 */
function getNodeAddress(node) {
  if (node.locations && node.locations.length > 0 && node.locations[0].type === 'absolute') {
    // for example: 0x400000
    return `0x${node.locations[0].value.toString(16).toUpperCase()}`
  }
  return null
}

/**
 * Formats bytes string for display
 * @param {Array} value - The bytes string
 * @returns {string} - Formatted bytes string
 */

function formatBytes(byteString) {
  // Use a regular expression to insert a space after every two characters
  const formattedString = byteString.replace(/(.{2})/g, '$1 ').trim();
  // convert to uppercase
  return formattedString.toUpperCase();
}

/**
 * Formats the address for dynamic flavor
 * @param {Array} value - The address value array
 * @returns {string} - Formatted address string
 */
function formatDynamicAddress(value) {
  const parts = ['ppid', 'pid', 'tid', 'id']
  return value
    .map((item, index) => `${parts[index]}:${item}`)
    .reverse()
    .join(' ← ')
}

function formatStaticAddress(address) {
  return `0x${address.toString(16).toUpperCase()}`
}
