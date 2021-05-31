import textwrap

import capa.rules
from capa.render import convert_meta_to_result_document
from capa.render.utils import format_parts_id


def test_render_meta_attack():
    # Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
    id = "T1543.003"
    tactic = "Persistence"
    technique = "Create or Modify System Process"
    subtechnique = "Windows Service"
    canonical = "{:s}::{:s}::{:s} [{:s}]".format(tactic, technique, subtechnique, id)

    rule = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            att&ck:
              - {:s}
          features:
            - number: 1
        """.format(
            canonical
        )
    )
    r = capa.rules.Rule.from_yaml(rule)
    rule_meta = convert_meta_to_result_document(r.meta)
    attack = rule_meta["att&ck"][0]

    assert attack["id"] == id
    assert attack["tactic"] == tactic
    assert attack["technique"] == technique
    assert attack["subtechnique"] == subtechnique

    assert format_parts_id(attack) == canonical


def test_render_meta_mbc():
    # Defense Evasion::Disable or Evade Security Tools::Heavens Gate [F0004.008]
    id = "F0004.008"
    objective = "Defense Evasion"
    behavior = "Disable or Evade Security Tools"
    method = "Heavens Gate"
    canonical = "{:s}::{:s}::{:s} [{:s}]".format(objective, behavior, method, id)

    rule = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            mbc:
              - {:s}
          features:
            - number: 1
        """.format(
            canonical
        )
    )
    r = capa.rules.Rule.from_yaml(rule)
    rule_meta = convert_meta_to_result_document(r.meta)
    attack = rule_meta["mbc"][0]

    assert attack["id"] == id
    assert attack["objective"] == objective
    assert attack["behavior"] == behavior
    assert attack["method"] == method

    assert format_parts_id(attack) == canonical
