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
Data-driven feature snapshot tests.

For every entry in `tests/fixtures/snapshots/features/manifest.json`, this
module regenerates a capa freeze from the corresponding sample via
`capa.features.freeze.main --reproducible`, compares it byte-for-byte
against the committed `.frz` file, and on mismatch renders a unified diff
of the freeze contents so a reviewer can see which features appeared,
disappeared, or moved.

A failing test means capa now extracts different features from the same
sample than it used to. That can be intentional (you changed an extractor)
or accidental (an unrelated change perturbed extraction); see the failure
message for how to update the fixture or investigate.

Refreshing a fixture after an intentional change::

    python -m capa.features.freeze --reproducible \\
        tests/data/<sample> tests/fixtures/snapshots/features/<name>.frz

The manifest is edited by hand when samples are added or removed.
"""

from __future__ import annotations

import json
import zlib
import difflib
import tempfile
from typing import Any, Optional
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

import capa.features.freeze

TESTS_DIR = Path(__file__).resolve().parent
TESTS_DATA_DIR = TESTS_DIR / "data"
FEATURE_SNAPSHOTS_DIR = TESTS_DATA_DIR / "fixtures" / "snapshots" / "features"
MANIFEST_PATH = FEATURE_SNAPSHOTS_DIR / "manifest.json"


class FeatureSnapshot(BaseModel):
    """One entry in the feature snapshot manifest."""

    model_config = ConfigDict(frozen=True)

    name: str
    sample: str
    freeze: str
    explanation: str = ""
    # Git commit at which this fixture was last regenerated. Purely informational:
    # on test failure we surface it so a reviewer can run `git log <commit>..HEAD`
    # to see what's changed since. Not validated — humans keep it accurate.
    generated_at_commit: Optional[str] = None
    format: Optional[str] = None
    backend: Optional[str] = None
    os: Optional[str] = None

    @property
    def sample_path(self) -> Path:
        return TESTS_DATA_DIR / self.sample

    @property
    def freeze_path(self) -> Path:
        return FEATURE_SNAPSHOTS_DIR / self.freeze


class Manifest(BaseModel):
    version: int = 1
    description: str = ""
    snapshots: list[FeatureSnapshot]

    @classmethod
    def from_file(cls, path: Path = MANIFEST_PATH) -> Manifest:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


_SNAPSHOTS = Manifest.from_file().snapshots


def _ids(snapshots: list[FeatureSnapshot]) -> list[str]:
    return [s.name for s in snapshots]


def _regenerate(snapshot: FeatureSnapshot) -> bytes:
    """Run the freeze CLI against the sample and return the produced bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "out.frz"
        argv = [str(snapshot.sample_path), str(out_path), "--reproducible"]
        if snapshot.format is not None:
            argv += ["--format", snapshot.format]
        if snapshot.backend is not None:
            argv += ["--backend", snapshot.backend]
        if snapshot.os is not None:
            argv += ["--os", snapshot.os]
        rc = capa.features.freeze.main(argv)
        if rc != 0:
            raise RuntimeError(f"capa.features.freeze.main exited with status {rc}")
        return out_path.read_bytes()


def _doc_to_lines(doc: dict[str, Any]) -> list[str]:
    """
    Render a freeze JSON document to a list of lines suitable for unified-diffing.

    We pretty-print with sorted keys so that field reordering (which is
    meaningful for features) is preserved while key ordering within objects is
    normalized.
    """
    return json.dumps(doc, indent=2, sort_keys=True).splitlines(keepends=True)


def _load_freeze_doc(buf: bytes) -> dict[str, Any]:
    """deserialize bytes to capa.features.freeze.Freeze, as JSON-like object.

    capa.features.freeze.loads() deserializes into a FeatureExtractor, not Freeze (or JSON, which we need for diffing).
    """
    magic = capa.features.freeze.MAGIC
    assert buf[: len(magic)] == magic, "missing freeze magic header"
    return json.loads(zlib.decompress(buf[len(magic) :]).decode("utf-8"))


def _format_mismatch(snapshot: FeatureSnapshot, expected: bytes, actual: bytes) -> str:
    """Build a failure message describing how the freezes differ."""
    lines = [
        f"feature snapshot drift for {snapshot.name!r}:",
        f"  sample:          {snapshot.sample}",
        f"  expected freeze: {snapshot.freeze_path}",
        "  actual  freeze:  <regenerated>",
    ]
    if snapshot.generated_at_commit:
        lines.append(f"  last regenerated at: {snapshot.generated_at_commit}")

    expected_doc = _load_freeze_doc(expected)
    actual_doc = _load_freeze_doc(actual)

    diff = list(
        difflib.unified_diff(
            _doc_to_lines(expected_doc),
            _doc_to_lines(actual_doc),
            fromfile=f"expected/{snapshot.freeze}",
            tofile=f"actual/{snapshot.freeze}",
            n=2,
        )
    )

    # Cap the diff so a wholly-changed snapshot doesn't dump thousands of lines
    # into the test output — the feature-count summary is enough for the common
    # case; regenerate the fixture locally to inspect the full diff.
    MAX_DIFF_LINES = 200
    lines.append("")
    if len(diff) > MAX_DIFF_LINES:
        lines.append(f"unified diff ({len(diff)} lines, truncated to {MAX_DIFF_LINES}):")
        diff = diff[:MAX_DIFF_LINES]
    else:
        lines.append(f"unified diff ({len(diff)} lines):")
    lines.extend(line.rstrip("\n") for line in diff)
    lines.append("")
    lines.append("how and when to update this snapshot:")
    lines.append("  If this change to feature extraction is INTENTIONAL (you edited an extractor):")
    lines.append("    1. regenerate the fixture:")
    lines.append(
        f"         python -m capa.features.freeze --reproducible \\\n"
        f"             {snapshot.sample_path} {snapshot.freeze_path}"
    )
    lines.append(
        "    2. update `generated_at_commit` in manifest.json to HEAD (the freeze CLI emits a suggested entry at INFO)."
    )
    lines.append("  If it is ACCIDENTAL (extraction shifted as a side effect of an unrelated change),")
    lines.append("    do NOT update the fixture; fix the root cause instead.")
    if snapshot.generated_at_commit:
        lines.append(
            f"  To see what's changed since this fixture was last regenerated:\n"
            f"         git log {snapshot.generated_at_commit}..HEAD -- capa/"
        )
    return "\n".join(lines)


@pytest.mark.parametrize("snapshot", _SNAPSHOTS, ids=_ids(_SNAPSHOTS))
def test_feature_snapshot(snapshot: FeatureSnapshot):
    """
    Regenerate the freeze for `snapshot.sample` and assert it matches
    `snapshot.freeze` byte-for-byte.
    """
    expected = snapshot.freeze_path.read_bytes()
    actual = _regenerate(snapshot)

    if actual == expected:
        return

    pytest.fail(_format_mismatch(snapshot, expected, actual))
