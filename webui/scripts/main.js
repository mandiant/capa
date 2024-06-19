/*
 * Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at: [package root]/LICENSE.txt
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */


// TODO(s-ff): simply all the functions and introduce smaller helper functions
// for creating elements, i.e. createOrStatement, isRangeStatement, .. etc.


/**
* Renders the JSON data representing the CAPA results into an HTML tree structure.
* @param {Object} json - The JSON data containing the CAPA results.
*/
function renderJSON(json) {
   const tree = document.getElementById('tree');

   // Iterate over each rule in the JSON
   for (const ruleName in json.rules) {
       const rule = json.rules[ruleName];

       // Create a list item for the matched rule
       const ruleElement = document.createElement('li');
       ruleElement.className = 'matched-rule';
       ruleElement.setAttribute('name', ruleName);

       // Create a details element for the rule
       const ruleDetails = document.createElement('details');

       // Create a summary element for the rule
       const ruleSummary = document.createElement('summary');

       // Create a div for the summary content
       const ruleSummaryContent = document.createElement('div');
       ruleSummaryContent.className = 'summary-content';

       // Add the statement type, rule title, and namespace to the summary content
       const statementType = document.createElement('span');
       statementType.className = 'statement-type';
       statementType.textContent = 'rule';
       ruleSummaryContent.appendChild(statementType);

       const ruleTitle = document.createElement('span');
       ruleTitle.className = 'rule-title';
       ruleTitle.setAttribute('source', rule.source);
       ruleTitle.textContent = rule.meta.name;
       ruleSummaryContent.appendChild(ruleTitle);

       const namespace = document.createElement('span');
       namespace.className = 'namespace';
       //namespace.textContent = rule.meta.namespace;
       if (rule.meta.namespace) {
           namespace.textContent = rule.meta.namespace;
       } else {
           namespace.style.display = 'none';
       }
       ruleSummaryContent.appendChild(namespace);

       // Append the summary content to the summary element
       ruleSummary.appendChild(ruleSummaryContent);

       // Append the summary element to the details element
       ruleDetails.appendChild(ruleSummary);

       // Create a list for the rule's matches
       const matchesList = document.createElement('ul');

       // Iterate over each match in the rule
       for (const match of rule.matches) {
           // Render the match and its children recursively
           const matchElement = renderMatch(match);
           matchesList.appendChild(matchElement);
       }

       // Append the matches list to the details element
       ruleDetails.appendChild(matchesList);

       // Append the rule details to the rule list item
       ruleElement.appendChild(ruleDetails);

       // Append the rule list item to the tree
       tree.appendChild(ruleElement);
   }
}

/**
* Recursively renders a match and its children into an HTML structure.
* @param {Object} match - The match object to be rendered.
* @returns {HTMLElement} The rendered match element.
*/
function renderMatch(match) {
   // Create a list item for the match
   const matchElement = document.createElement('li');
   matchElement.className = 'match-container';

   // Check if the match is a range statement
   if (match[1].node.type === 'statement' && match[1].node.statement.type === 'range') {
       const rangeElement = document.createElement('li');
       rangeElement.className = 'match-container';

       const rangeType = document.createElement('span');
       rangeType.className = 'feature-type';
       rangeType.textContent = `count(${match[1].node.statement.child.type}(${match[1].node.statement.child[match[1].node.statement.child.type]}))`;
       rangeElement.appendChild(rangeType);

       const rangeValue = document.createElement('span');
       rangeValue.className = 'feature-value';
       const minima = match[1].node.statement.min
       const maxima = match[1].node.statement.max
       if (minima == maxima) {
           rangeValue.textContent = `${minima}`;
           rangeType.textContent = `count(${match[1].node.statement.child.type})`;
       } else {
           rangeValue.textContent = `${minima} or more`;
       }
       rangeElement.appendChild(rangeValue);

       const rangeLocation = document.createElement('span');
       rangeLocation.className = 'feature-location';
       if (match[1].locations[0].value) {
           const locations = match[1].locations.map(loc => '0x' + loc.value.toString(16).toUpperCase());
           rangeLocation.textContent = locations.join(', ');
       }
       rangeElement.appendChild(rangeLocation);

       return rangeElement;
   }

   // If the match is a feature, render its type and value
   if (match[1].node.type === 'feature') {
       const featureType = document.createElement('span');
       featureType.className = 'feature-type';
       featureType.textContent = match[1].node.feature.type;
       matchElement.appendChild(featureType);

       const featureValue = document.createElement('span');
       featureValue.className = 'feature-value';
       featureValue.textContent = match[1].node.feature[match[1].node.feature.type];
       matchElement.appendChild(featureValue);

       const featureLocation = document.createElement('span');
       featureLocation.className = 'feature-location';
       if (match[1].locations[0].value) {
           const locations = match[1].locations.map(loc => '0x' + loc.value.toString(16).toUpperCase());
           featureLocation.textContent = locations.join(', ');
       }
       matchElement.appendChild(featureLocation);

   } else {
       // Check if the match is an optional statement - these always have `success: true`.
       const isOptional = match[1].node.statement.type === 'optional';

       // If it's an optional statement, check if any of its children have success set to true
       if (isOptional) {
           const hasSuccessfulChild = match[1].children.some(child => child.success);

           // If none of the children have success set to true, don't render the optional statement
           if (!hasSuccessfulChild) {
               return null;
           }
       }

       // Create a details element for the match
       const matchDetails = document.createElement('details');

       // Create a summary element for the match
       const matchSummary = document.createElement('summary');

       // Create a div for the summary content
       const matchSummaryContent = document.createElement('div');
       matchSummaryContent.className = 'summary-content';

       // Add the statement type to the summary content
       const statementType = document.createElement('span');
       statementType.className = 'statement-type';
       statementType.textContent = match[1].node.statement.type;
       matchSummaryContent.appendChild(statementType);

       // Append the summary content to the summary element
       matchSummary.appendChild(matchSummaryContent);

       // Append the summary element to the details element
       matchDetails.appendChild(matchSummary);

       // Create a list for the match's children
       const childrenList = document.createElement('ul');

       // Iterate over each child in the match
       for (const child of match[1].children) {
           // Recursively render the child if it is successful
           if (child.success) {
               const childElement = renderMatch([null, child]);
               if (childElement !== null) {
                   childrenList.appendChild(childElement);
               }
           }
       }

       // Append the children list to the details element
       matchDetails.appendChild(childrenList);

       // Append the match details to the match list item
       matchElement.appendChild(matchDetails);
   }

   return matchElement;
}

/**
* Determines the statement type based on the feature object.
* @param {Object} feature - The feature object.
* @returns {string} The statement type.
*/
function getStatementType(feature) {
   if (feature.type === 'and' || feature.type === 'or' || feature.type === 'not') {
       return feature.type;
   } else if (feature.match) {
       return 'match';
   } else {
       return 'feature';
   }
}

/**
* Checks if the given feature is a leaf feature (i.e., not a compound feature).
* @param {Object} feature - The feature object.
* @returns {boolean} True if the feature is a leaf feature, false otherwise.
*/
function isLeafFeature(feature) {
   return feature.type !== 'and' && feature.type !== 'or' && feature.type !== 'not' && !feature.match;
}

/**
* Adds a metadata table to the document body.
* @param {Object} metadata - The metadata object containing sample and analysis information.
*/
function addMetadataTable(metadata) {
   const metadataContainer = document.createElement("div");
   metadataContainer.className = "metadata-container";

   const table = document.createElement("table");
   table.className = "metadata-table";

   const rows = [{
           key: "MD5",
           value: metadata.sample.md5
       },
       {
           key: "SHA1",
           value: metadata.sample.sha1
       },
       {
           key: "SHA256",
           value: metadata.sample.sha256
       },
       {
           key: "Extractor",
           value: metadata.analysis.extractor
       },
       {
           key: "Analysis",
           value: metadata.flavor
       },
       {
           key: "OS",
           value: metadata.analysis.os
       },
       {
           key: "Format",
           value: metadata.analysis.format
       },
       {
           key: "Arch",
           value: metadata.analysis.arch
       },
       {
           key: "Path",
           value: metadata.sample.path
       },
       {
           key: "Base Address",
           value: "0x" + metadata.analysis.base_address.value.toString(16)
       },
       {
           key: "Version",
           value: metadata.version
       },
       {
           key: "Timestamp",
           value: metadata.timestamp
       },
       {
           key: "Function Count",
           value: Object.keys(metadata.analysis.feature_counts).length
       }
   ];

   rows.forEach((row) => {
       const tr = document.createElement("tr");
       const keyTd = document.createElement("td");
       keyTd.textContent = row.key;
       tr.appendChild(keyTd);
       const valueTd = document.createElement("td");
       valueTd.textContent = row.value;
       tr.appendChild(valueTd);
       table.appendChild(tr);
   });

   metadataContainer.appendChild(table);
   document.body.insertBefore(metadataContainer, document.querySelector("h1"));
}

// TODO(s-ff): introduce a "Upload from local" and "Load from URL" options
/* For now we are using a static al-khaser_64.exe rdoc for testing */
let url = 'https://raw.githubusercontent.com/mandiant/capa-testfiles/master/rd/al-khaser_x64.exe_.json';

fetch(url)
   .then(res => res.json())
   .then(result_document => {
       addMetadataTable(result_document.meta);
       renderJSON(result_document);
   })
   .catch(err => {
       throw err
   });
