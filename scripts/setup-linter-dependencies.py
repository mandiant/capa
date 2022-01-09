import json
from os.path import dirname

import requests
from stix2 import Filter, MemoryStore, AttackPattern


class MitreExtractor:
    url = ""
    kill_chain_name = ""

    def __init__(self):
        if self.kill_chain_name == "":
            raise ValueError(f"Kill chain name not specified in class {self.__class__.__name__}")

        if self.url == "":
            raise ValueError(f"URL not specified in class {self.__class__.__name__}")

        stix_json = requests.get(self.url).json()
        self._memory_store = MemoryStore(stix_data=stix_json["objects"])

    @staticmethod
    def _remove_deprecated_objetcs(stix_objects) -> list[AttackPattern]:
        """Remove any revoked or deprecated objects from queries made to the data source"""
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects,
            )
        )

    def _get_tactics(self) -> list[dict]:
        # Only one matrix for enterprise att&ck framework
        matrix = self._remove_deprecated_objetcs(
            self._memory_store.query(
                [
                    Filter("type", "=", "x-mitre-matrix"),
                ]
            )
        )[0]
        return list(map(self._memory_store.get, matrix["tactic_refs"]))

    def _get_techniques_from_tactic(self, tactic: str) -> list[AttackPattern]:
        techniques = self._remove_deprecated_objetcs(
            self._memory_store.query(
                [
                    Filter("type", "=", "attack-pattern"),
                    Filter("kill_chain_phases.phase_name", "=", tactic),
                    Filter(  # kill chain name for enterprise att&ck
                        "kill_chain_phases.kill_chain_name", "=", self.kill_chain_name
                    ),
                ]
            )
        )
        return techniques

    def _get_parent_technique_from_subtechnique(self, technique: AttackPattern) -> AttackPattern:
        sub_id = technique["external_references"][0]["external_id"].split(".")[0]
        parent_technique = self._remove_deprecated_objetcs(
            self._memory_store.query(
                [
                    Filter("type", "=", "attack-pattern"),
                    Filter("external_references.external_id", "=", sub_id),
                ]
            )
        )[0]
        return parent_technique

    def run(self) -> dict[str, dict[str, str]]:
        data: dict[str, dict[str, str]] = {}
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
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    kill_chain_name = "mitre-attack"


class MbcExtractor(MitreExtractor):
    url = "https://raw.githubusercontent.com/MBCProject/mbc-stix2/master/mbc/mbc.json"
    kill_chain_name = "mitre-mbc"

    def _get_tactics(self) -> list[dict]:
        tactics = super(MbcExtractor, self)._get_tactics()
        # We don't want the Micro-objective string inside objective names
        for tactic in tactics:
            tactic["name"] = tactic["name"].replace(" Micro-objective", "")
        return tactics


def main():
    data = {"att&ck": AttckExtractor().run(), "mbc": MbcExtractor().run()}

    with open(f"{dirname(__file__)}/linter-data.json", "w") as jf:
        json.dump(data, jf, indent=2)


if __name__ == "__main__":
    main()
