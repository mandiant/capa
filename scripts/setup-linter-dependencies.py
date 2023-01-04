"""
Generate capa linter-data.json, used to validate Att&ck/MBC IDs and names.

Use the --extractor option to extract data from Att&ck or MBC (or both) frameworks.
Use the --output to choose the output json file.
By default, the script will create a linter-data.json in the scripts/ directory for both frameworks.

Note: The capa rules linter will try to load from its default location (scripts/linter-data.json).

Usage:

    usage: setup-linter-dependencies.py [-h] [--extractor {both,mbc,att&ck}] [--output OUTPUT]

    Setup linter dependencies.

    optional arguments:
      -h, --help            show this help message and exit
      --extractor {both,mbc,att&ck}
                            Extractor that will be run
      --output OUTPUT, -o OUTPUT
                            Path to output file (lint.py will be looking for linter-data.json)


Example:

    $ python3 setup-linter-dependencies.py
    2022-01-24 22:35:06,901 [INFO] Extracting Mitre Att&ck techniques...
    2022-01-24 22:35:06,901 [INFO] Downloading STIX data at: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    2022-01-24 22:35:13,001 [INFO] Starting extraction...
    2022-01-24 22:35:39,395 [INFO] Extracting MBC behaviors...
    2022-01-24 22:35:39,395 [INFO] Downloading STIX data at: https://raw.githubusercontent.com/MBCProject/mbc-stix2/master/mbc/mbc.json
    2022-01-24 22:35:39,839 [INFO] Starting extraction...
    2022-01-24 22:35:42,632 [INFO] Writing results to linter-data.json
"""
import json
import logging
import argparse
from sys import argv
from typing import Dict, List
from os.path import dirname

import requests
from stix2 import Filter, MemoryStore, AttackPattern  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class MitreExtractor:
    """
    This class extract Mitre techniques and sub techniques that are represented as "attack-pattern" in STIX format.
    The STIX data is collected in JSON format by requesting the specified URL.

    url: must point to json stix location
    kill_chain_name: mitre-attack, mitre-mbc...
    """

    url = ""
    kill_chain_name = ""

    def __init__(self):
        """Download and store in memory the STIX data on instantiation."""
        if self.kill_chain_name == "":
            raise ValueError(f"Kill chain name not specified in class {self.__class__.__name__}")

        if self.url == "":
            raise ValueError(f"URL not specified in class {self.__class__.__name__}")

        logging.info(f"Downloading STIX data at: {self.url}")
        stix_json = requests.get(self.url).json()
        self._memory_store = MemoryStore(stix_data=stix_json["objects"])

    @staticmethod
    def _remove_deprecated_objects(stix_objects) -> List[AttackPattern]:
        """Remove any revoked or deprecated objects from queries made to the data source."""
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects,
            )
        )

    def _get_tactics(self) -> List[Dict]:
        """Get tactics IDs from Mitre matrix."""
        # Only one matrix for enterprise att&ck framework
        matrix = self._remove_deprecated_objects(
            self._memory_store.query(
                [
                    Filter("type", "=", "x-mitre-matrix"),
                ]
            )
        )[0]
        return list(map(self._memory_store.get, matrix["tactic_refs"]))

    def _get_techniques_from_tactic(self, tactic: str) -> List[AttackPattern]:
        """Get techniques and sub techniques from a Mitre tactic (kill_chain_phases->phase_name)"""
        techniques = self._remove_deprecated_objects(
            self._memory_store.query(
                [
                    Filter("type", "=", "attack-pattern"),
                    Filter("kill_chain_phases.phase_name", "=", tactic),
                    Filter("kill_chain_phases.kill_chain_name", "=", self.kill_chain_name),
                ]
            )
        )
        return techniques

    def _get_parent_technique_from_subtechnique(self, technique: AttackPattern) -> AttackPattern:
        """Get parent technique of a sub technique using the technique ID TXXXX.YYY"""
        sub_id = technique["external_references"][0]["external_id"].split(".")[0]
        parent_technique = self._remove_deprecated_objects(
            self._memory_store.query(
                [
                    Filter("type", "=", "attack-pattern"),
                    Filter("external_references.external_id", "=", sub_id),
                ]
            )
        )[0]
        return parent_technique

    def run(self) -> Dict[str, Dict[str, str]]:
        """Iterate over every technique over every tactic. If the technique is a sub technique, then
        we also search for the parent technique name.
        """
        logging.info("Starting extraction...")
        data: Dict[str, Dict[str, str]] = {}
        for tactic in self._get_tactics():
            data[tactic["name"]] = {}
            for technique in self._get_techniques_from_tactic(tactic["x_mitre_shortname"]):
                tid = technique["external_references"][0]["external_id"]
                technique_name = technique["name"].split("::")[0]
                if technique["x_mitre_is_subtechnique"]:
                    parent_technique = self._get_parent_technique_from_subtechnique(technique)
                    data[tactic["name"]][tid] = f"{parent_technique['name']}::{technique_name}"
                else:
                    data[tactic["name"]][tid] = technique_name
        return data


class AttckExtractor(MitreExtractor):
    """Extractor for the Mitre Enterprise Att&ck Framework."""

    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    kill_chain_name = "mitre-attack"


class MbcExtractor(MitreExtractor):
    """Extractor for the Mitre Malware Behavior Catalog."""

    url = "https://raw.githubusercontent.com/MBCProject/mbc-stix2/master/mbc/mbc.json"
    kill_chain_name = "mitre-mbc"

    def _get_tactics(self) -> List[Dict]:
        """Override _get_tactics to edit the tactic name for Micro-objective"""
        tactics = super()._get_tactics()
        # We don't want the Micro-objective string inside objective names
        for tactic in tactics:
            tactic["name"] = tactic["name"].replace(" Micro-objective", "")
        return tactics


def main(args: argparse.Namespace) -> None:
    data = {}
    if args.extractor == "att&ck" or args.extractor == "both":
        logging.info("Extracting Mitre Att&ck techniques...")
        data["att&ck"] = AttckExtractor().run()
    if args.extractor == "mbc" or args.extractor == "both":
        logging.info("Extracting MBC behaviors...")
        data["mbc"] = MbcExtractor().run()

    logging.info(f"Writing results to {args.output}")
    try:
        with open(args.output, "w") as jf:
            json.dump(data, jf, indent=2)
    except BaseException as e:
        logging.error(f"Exception encountered when writing results: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Setup linter dependencies.")
    parser.add_argument(
        "--extractor", type=str, choices=["both", "mbc", "att&ck"], default="both", help="Extractor that will be run"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=f"{dirname(__file__)}/linter-data.json",
        help="Path to output file (lint.py will be looking for linter-data.json)",
    )
    main(parser.parse_args(args=argv[1:]))
