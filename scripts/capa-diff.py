#!/usr/bin/env python3
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
capa-diff.py

Compare capabilities between two capa JSON result documents.

Example:

    $ capa --json old.exe > old.json
    $ capa --json new.exe > new.json
    $ python scripts/capa-diff.py old.json new.json
    added capabilities: 2
      + anti-debug via timeout
      + inject process
    removed capabilities: 1
      - check for mutex
"""

from __future__ import annotations

import json
import sys
import argparse
from pathlib import Path

import capa.render.utils as rutils
import capa.render.default as rdefault
import capa.render.result_document as rd


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare capabilities in two capa JSON result documents.")
    parser.add_argument("old", type=Path, help="path to older/baseline capa JSON result document")
    parser.add_argument("new", type=Path, help="path to newer/target capa JSON result document")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="render output as text or json (default: text)",
    )
    parser.add_argument(
        "--include-subscope-rules",
        action="store_true",
        help="include rules that only matched as subrule references",
    )
    return parser.parse_args(argv)


def _load_result_document(path: Path) -> rd.ResultDocument:
    return rd.ResultDocument.model_validate_json(path.read_text(encoding="utf-8"))


def _collect_capabilities(doc: rd.ResultDocument, include_subscope_rules: bool = False) -> dict[str, dict[str, object]]:
    hidden = set()
    if not include_subscope_rules:
        hidden = rdefault.find_subrule_matches(doc)

    capabilities: dict[str, dict[str, object]] = {}
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in hidden:
            continue

        capabilities[rule.meta.name] = {
            "name": rule.meta.name,
            "namespace": rule.meta.namespace,
            "match_count": len(rule.matches),
        }
    return capabilities


def _render_text(added: list[dict[str, object]], removed: list[dict[str, object]]) -> str:
    lines = [f"added capabilities: {len(added)}"]
    for capability in added:
        lines.append(f"  + {capability['name']}")

    lines.append(f"removed capabilities: {len(removed)}")
    for capability in removed:
        lines.append(f"  - {capability['name']}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    args = _parse_args(argv)
    old_doc = _load_result_document(args.old)
    new_doc = _load_result_document(args.new)

    old_caps = _collect_capabilities(old_doc, include_subscope_rules=args.include_subscope_rules)
    new_caps = _collect_capabilities(new_doc, include_subscope_rules=args.include_subscope_rules)

    added = sorted((new_caps[name] for name in (set(new_caps) - set(old_caps))), key=lambda c: c["name"])
    removed = sorted((old_caps[name] for name in (set(old_caps) - set(new_caps))), key=lambda c: c["name"])

    if args.output_format == "json":
        print(json.dumps({"added": added, "removed": removed}, indent=2))
    else:
        print(_render_text(added, removed))

    return 0


if __name__ == "__main__":
    sys.exit(main())
