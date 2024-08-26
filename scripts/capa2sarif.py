# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Convert capa json output to sarif schema
    usage: capa2sarif.py [-h] [-g] [-r] [-t TAG] [--version] capa_output

Capa to SARIF analysis file
positional arguments:
    capa_output         Path to capa JSON output file
optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -t TAG, --tag TAG     filter on rule meta field values (ruleid)

Requires:
    - sarif_om 1.0.4
    - jschema_to_python 1.2.3
"""
import sys
import json
import logging
import argparse
from typing import List, Optional
from pathlib import Path

from capa.version import __version__

logger = logging.getLogger("capa2sarif")

# Dependencies
try:
    from sarif_om import Run, Tool, SarifLog, ToolComponent
except ImportError as e:
    logger.error(
        "Required import `sarif_om` is not installed. This is solved by installing `python3 -m pip install sarif_om>=1.0.4`. %s",
        e,
    )
    exit(-4)

try:
    from jschema_to_python.to_json import to_json
except ImportError as e:
    logger.error(
        "Required import `jschema_to_python` is not installed. This is solved by installing `python3 -m pip install jschema_to_python>=1.2.3`, %s",
        e,
    )
    exit(-4)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capa to SARIF analysis file")

    # Positional argument
    parser.add_argument("capa_output", help="Path to capa JSON output file")

    # Optional arguments
    parser.add_argument(
        "-g",
        "--ghidra-compat",
        action="store_true",
        help="Compatibility for Ghidra 11.0.X",
    )
    parser.add_argument(
        "-r",
        "--radare-compat",
        action="store_true",
        help="Compatibility for Radare r2sarif plugin v2.0",
    )
    parser.add_argument("-t", "--tag", help="Filter on rule meta field values (ruleid)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    args = _parse_args()

    try:
        json_data = json.loads(Path(args.capa_output).read_text(encoding="utf-8"))
    except ValueError:
        logger.error("Input data was not valid JSON, input should be a capa json output file.")
        return -1
    except json.JSONDecodeError:
        # An exception has occured
        logger.error("Input data was not valid JSON, input should be a capa json output file.")
        return -2

    # Marshall json into Sarif
    # Create baseline sarif structure to be populated from json data
    sarif_structure: Optional[dict] = _sarif_boilerplate(json_data["meta"], json_data["rules"])
    if sarif_structure is None:
        logger.error("An Error has occured creating default sarif structure.")
        return -3

    _populate_artifact(sarif_structure, json_data["meta"])
    _populate_invocations(sarif_structure, json_data["meta"])
    _populate_results(sarif_structure, json_data["rules"], args.ghidra_compat)

    if args.ghidra_compat:
        # Ghidra can't handle this structure as of 11.0.x
        if "invocations" in sarif_structure["runs"][0]:
            del sarif_structure["runs"][0]["invocations"]

        # artifacts must include a description as well with a text field.
        if "artifacts" in sarif_structure["runs"][0]:
            sarif_structure["runs"][0]["artifacts"][0]["description"] = {"text": "placeholder"}

        # For better compliance with Ghidra table. Iteraction through properties['additionalProperties']
        """
        "additionalProperties": {
            "to": "<hex addr>",
            "offset": 0,
            "primary": true,
            "index": <>"",
            "kind": "<kind column value>",
            "opIndex": 0,
            "sourceType": ""
        }
    """

    if args.radare_compat:
        # Add just enough for passing tests
        _add_filler_optional(json_data, sarif_structure)

    print(json.dumps(sarif_structure, indent=4))  # noqa: T201
    return 0


def _sarif_boilerplate(data_meta: dict, data_rules: dict) -> Optional[dict]:
    # Only track rules that appear in this log, not full 1k
    rules = []
    # Parse rules from parsed sarif structure
    for key in data_rules:
        # Use attack as default, if both exist then only use attack, if neither exist use the name of rule for ruleID
        #   this is not good practice to use long name for ruleID
        attack_length = len(data_rules[key]["meta"]["attack"])
        mbc_length = len(data_rules[key]["meta"]["mbc"])
        if attack_length or mbc_length:
            id = (
                data_rules[key]["meta"]["attack"][0]["id"]
                if attack_length > 0
                else data_rules[key]["meta"]["mbc"][0]["id"]
            )
        else:
            id = data_rules[key]["meta"]["name"]

        # Append current rule
        rules.append(
            {
                # Default to attack identifier, fall back to MBC, mainly relevant if both are present
                "id": id,
                "name": data_rules[key]["meta"]["name"],
                "shortDescription": {"text": data_rules[key]["meta"]["name"]},
                "messageStrings": {"default": {"text": data_rules[key]["meta"]["name"]}},
                "properties": {
                    "namespace": data_rules[key]["meta"]["namespace"] if "namespace" in data_rules[key]["meta"] else [],
                    "scopes": data_rules[key]["meta"]["scopes"],
                    "references": data_rules[key]["meta"]["references"],
                    "lib": data_rules[key]["meta"]["lib"],
                },
            }
        )

    tool = Tool(
        driver=ToolComponent(
            name="Capa",
            version=__version__,
            information_uri="https://github.com/mandiant/capa",
            rules=rules,
        )
    )

    # Create a SARIF Log object, populate with a single run
    sarif_log = SarifLog(
        version="2.1.0",
        schema_uri="https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        runs=[Run(tool=tool, results=[], artifacts=[], invocations=[])],
    )

    # Convert the SARIF log to a dictionary and then to a JSON string
    try:
        sarif_outline = json.loads(to_json(sarif_log))
    except json.JSONDecodeError:
        # An exception has occured
        return None

    return sarif_outline


def _populate_artifact(sarif_log: dict, meta_data: dict) -> None:
    """
    @param sarif_log: dict - sarif data structure including runs
    @param meta_data: dict - Capa meta output
    @returns None, updates sarif_log via side-effects
    """
    sample = meta_data["sample"]
    artifact = {
        "location": {"uri": sample["path"]},
        "roles": ["analysisTarget"],
        "hashes": {
            "md5": sample["md5"],
            "sha-1": sample["sha1"],
            "sha-256": sample["sha256"],
        },
    }
    sarif_log["runs"][0]["artifacts"].append(artifact)


def _populate_invocations(sarif_log: dict, meta_data: dict) -> None:
    """
    @param sarif_log: dict - sarif data structure including runs
    @param meta_data: dict - Capa meta output
    @returns None, updates sarif_log via side-effects
    """
    analysis_time = meta_data["timestamp"]
    argv = meta_data["argv"]
    analysis = meta_data["analysis"]
    invoke = {
        "commandLine": "capa " + " ".join(argv),
        "arguments": argv if len(argv) > 0 else [],
        # Format in Zulu time, this may require a conversion from local timezone
        "endTimeUtc": f"{analysis_time}Z",
        "executionSuccessful": True,
        "properties": {
            "format": analysis["format"],
            "arch": analysis["arch"],
            "os": analysis["os"],
            "extractor": analysis["extractor"],
            "rule_location": analysis["rules"],
            "base_address": analysis["base_address"],
        },
    }
    sarif_log["runs"][0]["invocations"].append(invoke)


def _enumerate_evidence(node: dict, related_count: int) -> List[dict]:
    related_locations = []
    if node.get("success") and node.get("node", {}).get("type") != "statement":
        label = ""
        if node.get("node", {}).get("type") == "feature":
            if node.get("node", {}).get("feature", {}).get("type") == "api":
                label = "api: " + node.get("node", {}).get("feature", {}).get("api")
            elif node.get("node", {}).get("feature", {}).get("type") == "match":
                label = "match: " + node.get("node", {}).get("feature", {}).get("match")
            elif node.get("node", {}).get("feature", {}).get("type") == "number":
                label = f"number: {node.get('node', {}).get('feature', {}).get('description')} ({node.get('node', {}).get('feature', {}).get('number')})"
            elif node.get("node", {}).get("feature", {}).get("type") == "offset":
                label = f"offset: {node.get('node', {}).get('feature', {}).get('description')} ({node.get('node', {}).get('feature', {}).get('offset')})"
            elif node.get("node", {}).get("feature", {}).get("type") == "mnemonic":
                label = f"mnemonic: {node.get('node', {}).get('feature', {}).get('mnemonic')}"
            elif node.get("node", {}).get("feature", {}).get("type") == "characteristic":
                label = f"characteristic: {node.get('node', {}).get('feature', {}).get('characteristic')}"
            elif node.get("node", {}).get("feature", {}).get("type") == "os":
                label = f"os: {node.get('node', {}).get('feature', {}).get('os')}"
            elif node.get("node", {}).get("feature", {}).get("type") == "operand number":
                label = f"operand: ({node.get('node', {}).get('feature', {}).get('index')} ) {node.get('node', {}).get('feature', {}).get('description')} ({node.get('node', {}).get('feature', {}).get('operand_number')})"
            else:
                logger.error(
                    "Not implemented %s",
                    node.get("node", {}).get("feature", {}).get("type"),
                )
                return []
        else:
            logger.error("Not implemented %s", node.get("node", {}).get("type"))
            return []

        for loc in node.get("locations", []):
            if loc["type"] != "absolute":
                continue

            related_locations.append(
                {
                    "id": related_count,
                    "message": {"text": label},
                    "physicalLocation": {"address": {"absoluteAddress": loc["value"]}},
                }
            )
            related_count += 1

    if node.get("success") and node.get("node", {}).get("type") == "statement":
        for child in node.get("children", []):
            related_locations += _enumerate_evidence(child, related_count)

    return related_locations


def _populate_results(sarif_log: dict, data_rules: dict, ghidra_compat: bool) -> None:
    """
    @param sarif_log: dict - sarif data structure including runs
    @param meta_data: dict - Capa meta output
    @returns None, updates sarif_log via side-effects
    """
    results = sarif_log["runs"][0]["results"]

    # Parse rules from parsed sarif structure
    for key in data_rules:
        # Use attack as default, if both exist then only use attack, if neither exist use the name of rule for ruleID
        #   this is not good practice to use long name for ruleID.
        attack_length = len(data_rules[key]["meta"]["attack"])
        mbc_length = len(data_rules[key]["meta"]["mbc"])
        if attack_length or mbc_length:
            id = (
                data_rules[key]["meta"]["attack"][0]["id"]
                if attack_length > 0
                else data_rules[key]["meta"]["mbc"][0]["id"]
            )
        else:
            id = data_rules[key]["meta"]["name"]

        for address, details in data_rules[key]["matches"]:
            related_cnt = 0
            related_locations = _enumerate_evidence(details, related_cnt)

            res = {
                "ruleId": id,
                "level": "none" if not ghidra_compat else "NONE",
                "message": {"text": data_rules[key]["meta"]["name"]},
                "kind": "informational" if not ghidra_compat else "INFORMATIONAL",
                "locations": [
                    {
                        "physicalLocation": {
                            "address": {
                                "absoluteAddress": address["value"],
                            }
                        },
                    }
                ],
            }
            if not ghidra_compat:
                res["relatedLocations"] = related_locations

            results.append(res)


def _add_filler_optional(capa_result: dict, sarif_log: dict) -> None:
    """Update sarif file with just enough fields to pass radare tests"""
    base_address = capa_result["meta"]["analysis"]["base_address"]["value"]
    # Assume there is only one run, and one binary artifact
    artifact = sarif_log["runs"][0]["artifacts"][0]
    if "properties" not in artifact:
        artifact["properties"] = {}
    if "additionalProperties" not in artifact["properties"]:
        artifact["properties"]["additionalProperties"] = {}
    if "imageBase" not in artifact["properties"]["additionalProperties"]:
        artifact["properties"]["additionalProperties"]["imageBase"] = base_address


if __name__ == "__main__":
    sys.exit(main())
