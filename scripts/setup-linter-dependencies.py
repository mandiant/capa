import json

import requests
from stix2 import Filter, MemoryStore, AttackPattern


class StixExtractor:
    def __init__(self, url):
        stix_json = requests.get(url).json()
        self._memory_store = MemoryStore(stix_data=stix_json["objects"])

    def _process_attack_patterns(self, attack_patterns):
        return attack_patterns

    def _get_attack_patterns(self):
        results = self._memory_store.query([Filter("type", "=", "attack-pattern")])
        return self._process_attack_patterns(results)


class AttckStixExtractor(StixExtractor):
    def _process_attack_patterns(self, stix_objects) -> list[AttackPattern]:
        """Remove any revoked or deprecated objects from queries made to the data source"""
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects,
            )
        )

    def _get_tactics(self):
        # Only one matrix -> enterprise att&ck
        matrix = self._memory_store.query(
            [
                Filter("type", "=", "x-mitre-matrix"),
            ]
        )[0]
        return [self._memory_store.get(tid) for tid in matrix["tactic_refs"]]

    def _get_techniques_from_tactic(self, tactic):
        return self._memory_store.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("kill_chain_phases.phase_name", "=", tactic["x_mitre_shortname"]),
                Filter(
                    "kill_chain_phases.kill_chain_name", "=", "mitre-attack"
                ),  # kill chain name for enterprise att&ck
            ]
        )

    def _get_parent_technique_from_subtechnique(self, subtechnique):
        tid = subtechnique["external_references"][0]["external_id"].split(".")[0]
        return self._memory_store.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("external_references.external_id", "=", tid),
            ]
        )[0]

    def run(self):
        result = {}
        tactics = self._get_tactics()
        for tactic in tactics:
            result[tactic["name"]] = {}
            techniques = self._get_techniques_from_tactic(tactic)
            for technique in techniques:
                if technique["x_mitre_is_subtechnique"]:
                    parent_technique = self._get_parent_technique_from_subtechnique(technique)
                    result[tactic["name"]][f"{parent_technique['name']}::{technique['name']}"] = technique[
                        "external_references"
                    ][0]["external_id"]
                else:
                    result[tactic["name"]][technique["name"]] = technique["external_references"][0]["external_id"]
        return result


class MbcStixExtractor(StixExtractor):
    ...


def main():
    s = AttckStixExtractor(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )
    r = s.run()
    with open("attack.json", "w") as jf:
        json.dump(r, jf, indent=2)


if __name__ == "__main__":
    main()
