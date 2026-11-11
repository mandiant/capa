# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Data-driven rule match snapshot tests.

For every entry in `tests/fixtures/snapshots/matches/manifest.json`, this module
loads the committed feature freeze used by the feature snapshot tests, runs the
default ruleset against it, and compares the resulting rule matches against a
committed JSON fixture.

Feature extraction is already pinned by `tests/test_feature_snapshots.py`, so
reusing those freezes keeps the input fixed and isolates the behavior under test
here: rule matching. It also means these tests do not run a code analysis
backend, so they are fast and do not depend on vivisect.

A failing test means capa now reports different capabilities for the same
features. That can be intentional (you changed the engine, or synced the rules
submodule) or accidental; see the failure message for how to update the fixture
or investigate.

Refreshing fixtures after an intentional change::

    python tests/test_match_snapshots.py --regenerate
    python tests/test_match_snapshots.py --regenerate mimikatz-exe

The manifest is edited by hand when snapshots are added or removed.
"""

from __future__ import annotations

import json
import difflib
import logging
from typing import Optional
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

import capa.rules
import capa.features.freeze
import capa.capabilities.common
from capa.features.address import Address

logger = logging.getLogger(__name__)

TESTS_DIR = Path(__file__).resolve().parent
CAPA_DIR = TESTS_DIR.parent
RULES_DIR = CAPA_DIR / "rules"

# the freeze fixtures live in the capa-testfiles submodule, alongside the feature snapshots
FEATURE_SNAPSHOTS_DIR = TESTS_DIR / "data" / "fixtures" / "snapshots" / "features"

# the expected matches are small JSON documents, so they live in this repository,
# where they show up in review as a readable diff
MATCH_SNAPSHOTS_DIR = TESTS_DIR / "fixtures" / "snapshots" / "matches"
MANIFEST_PATH = MATCH_SNAPSHOTS_DIR / "manifest.json"


class MatchSnapshot(BaseModel):
    """One entry in the match snapshot manifest."""

    model_config = ConfigDict(frozen=True)

    name: str
    freeze: str
    matches: str
    explanation: str = ""
    # Commit of the `rules` submodule at which this fixture was last regenerated.
    # Purely informational: on failure we surface it so a reviewer can tell a rule
    # sync apart from an engine change. Not validated - humans keep it accurate.
    generated_at_rules_commit: Optional[str] = None

    @property
    def freeze_path(self) -> Path:
        return FEATURE_SNAPSHOTS_DIR / self.freeze

    @property
    def matches_path(self) -> Path:
        return MATCH_SNAPSHOTS_DIR / self.matches


class Manifest(BaseModel):
    version: int = 1
    description: str = ""
    snapshots: list[MatchSnapshot]

    @classmethod
    def from_file(cls, path: Path = MANIFEST_PATH) -> Manifest:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


_SNAPSHOTS = Manifest.from_file().snapshots


def _ids(snapshots: list[MatchSnapshot]) -> list[str]:
    return [s.name for s in snapshots]


def _load_ruleset() -> capa.rules.RuleSet:
    return capa.rules.get_rules([RULES_DIR])


@pytest.fixture(scope="session")
def default_ruleset() -> capa.rules.RuleSet:
    return _load_ruleset()


def _render_addresses(addresses: set[Address]) -> list[str]:
    """
    Render a set of addresses to a stable, readable list.

    `repr` is used because the integer-backed address types subclass `int`, so
    `str` would lose which kind of address it is.
    """
    return [repr(address) for address in sorted(addresses)]


def _compute_matches(snapshot: MatchSnapshot, ruleset: capa.rules.RuleSet) -> dict[str, list[str]]:
    """Run the ruleset against the committed freeze and render the matches."""
    extractor = capa.features.freeze.load(snapshot.freeze_path.read_bytes())
    capabilities = capa.capabilities.common.find_capabilities(ruleset, extractor, disable_progress=True)

    # subscope rules are an implementation detail: they are derived from their parent
    # rule and named with a hash of its content, so an unrelated edit to the parent
    # renames them. capa's own result document drops them too, so do the same here.
    #
    # a rule may match more than once at the same address, which is not what this
    # fixture is pinning, so record the distinct locations per rule.
    #
    # the JSON fixture is written with sorted keys, so ordering here does not matter.
    return {
        name: _render_addresses({address for address, _ in results})
        for name, results in capabilities.matches.items()
        if not ruleset.rules[name].is_subscope_rule()
    }


def _dumps(matches: dict[str, list[str]]) -> str:
    return json.dumps(matches, indent=2, sort_keys=True) + "\n"


def _format_mismatch(snapshot: MatchSnapshot, expected: dict[str, list[str]], actual: dict[str, list[str]]) -> str:
    """Build a failure message describing how the matches differ."""
    lines = [
        f"rule match snapshot drift for {snapshot.name!r}:",
        f"  freeze:           {snapshot.freeze_path}",
        f"  expected matches: {snapshot.matches_path}",
        f"  expected rules:   {len(expected)}",
        f"  actual rules:     {len(actual)}",
    ]
    if snapshot.generated_at_rules_commit:
        lines.append(f"  rules submodule at last regeneration: {snapshot.generated_at_rules_commit}")

    gained = sorted(set(actual) - set(expected))
    lost = sorted(set(expected) - set(actual))
    moved = sorted(name for name in set(actual) & set(expected) if actual[name] != expected[name])

    lines.append("")
    if gained:
        lines.append(f"rules that now match ({len(gained)}):")
        lines.extend(f"  + {name}" for name in gained[:20])
        if len(gained) > 20:
            lines.append(f"  ... and {len(gained) - 20} more")
    if lost:
        lines.append(f"rules that no longer match ({len(lost)}):")
        lines.extend(f"  - {name}" for name in lost[:20])
        if len(lost) > 20:
            lines.append(f"  ... and {len(lost) - 20} more")
    if moved:
        lines.append(f"rules that match at different locations ({len(moved)}):")
        lines.extend(f"  ~ {name}" for name in moved[:20])
        if len(moved) > 20:
            lines.append(f"  ... and {len(moved) - 20} more")

    MAX_DIFF_LINES = 200
    diff = list(
        difflib.unified_diff(
            _dumps(expected).splitlines(keepends=True),
            _dumps(actual).splitlines(keepends=True),
            fromfile=f"expected/{snapshot.matches}",
            tofile=f"actual/{snapshot.matches}",
            n=2,
        )
    )
    lines.append("")
    if len(diff) > MAX_DIFF_LINES:
        lines.append(f"unified diff ({len(diff)} lines, truncated to {MAX_DIFF_LINES}):")
        diff = diff[:MAX_DIFF_LINES]
    else:
        lines.append(f"unified diff ({len(diff)} lines):")
    lines.extend(line.rstrip("\n") for line in diff)

    lines.append("")
    lines.append("how and when to update this snapshot:")
    lines.append("  If this change to rule matching is INTENTIONAL (you changed the engine,")
    lines.append("  or synced the rules submodule):")
    lines.append("    1. regenerate the fixture:")
    lines.append(f"         python tests/test_match_snapshots.py --regenerate {snapshot.name}")
    lines.append("    2. update `generated_at_rules_commit` in manifest.json to the rules submodule commit:")
    lines.append("         git -C rules rev-parse HEAD")
    lines.append("    3. review the diff above: it is the real-world effect of your change.")
    lines.append("  If it is ACCIDENTAL, do NOT update the fixture; fix the root cause instead.")
    return "\n".join(lines)


@pytest.mark.parametrize("snapshot", _SNAPSHOTS, ids=_ids(_SNAPSHOTS))
def test_rule_match_snapshot(snapshot: MatchSnapshot, default_ruleset: capa.rules.RuleSet):
    """
    Match the default ruleset against `snapshot.freeze` and assert the resulting
    matches are those recorded in `snapshot.matches`.
    """
    expected = json.loads(snapshot.matches_path.read_text(encoding="utf-8"))
    actual = _compute_matches(snapshot, default_ruleset)

    if actual == expected:
        return

    pytest.fail(_format_mismatch(snapshot, expected, actual))


def _regenerate(names: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    selected = [s for s in _SNAPSHOTS if not names or s.name in names]
    if names:
        unknown = sorted(set(names) - {s.name for s in selected})
        if unknown:
            logger.error("unknown snapshot(s): %s", ", ".join(unknown))
            return 1

    rules = _load_ruleset()
    for snapshot in selected:
        matches = _compute_matches(snapshot, rules)
        snapshot.matches_path.write_text(_dumps(matches), encoding="utf-8")
        logger.info("wrote %d rule matches to %s", len(matches), snapshot.matches_path)

    logger.info("")
    logger.info("remember to update `generated_at_rules_commit` in %s", MANIFEST_PATH)
    logger.info("with the output of: git -C rules rev-parse HEAD")
    return 0


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="regenerate rule match snapshot fixtures")
    parser.add_argument("--regenerate", action="store_true", help="rewrite the committed match fixtures")
    parser.add_argument("names", nargs="*", help="snapshot names to regenerate (default: all)")
    args = parser.parse_args()

    if not args.regenerate:
        parser.error("nothing to do: pass --regenerate (run the tests with pytest)")

    sys.exit(_regenerate(args.names))
