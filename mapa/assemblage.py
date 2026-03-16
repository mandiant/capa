from __future__ import annotations

import csv
import logging
from collections import defaultdict
from pathlib import Path

from mapa.model import AssemblageRecord

logger = logging.getLogger(__name__)

REQUIRED_COLUMNS = frozenset({"hash", "name", "start", "end", "source_file"})


def validate_assemblage_columns(fieldnames: list[str] | None) -> None:
    columns = set(fieldnames or [])
    missing = sorted(REQUIRED_COLUMNS - columns)
    if missing:
        raise ValueError(
            f"assemblage CSV is missing required columns: {', '.join(missing)}"
        )


def load_assemblage_records(
    assemblage_path: Path,
    sample_sha256: str,
    base_address: int,
) -> dict[int, list[AssemblageRecord]]:
    if not sample_sha256:
        raise ValueError("sample sha256 is required to load assemblage data")

    normalized_sha256 = sample_sha256.lower()
    records_by_address: defaultdict[int, list[AssemblageRecord]] = defaultdict(list)
    seen_by_address: defaultdict[int, set[AssemblageRecord]] = defaultdict(set)

    with assemblage_path.open("rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        validate_assemblage_columns(reader.fieldnames)
        for row in reader:
            row_hash = (row.get("hash") or "").strip().lower()
            if row_hash != normalized_sha256:
                continue

            record = AssemblageRecord.from_csv_row(row, base_address=base_address)
            seen = seen_by_address[record.address]
            if record in seen:
                continue
            seen.add(record)
            records_by_address[record.address].append(record)

    logger.debug(
        "loaded %d assemblage records for %s from %s",
        sum(len(records) for records in records_by_address.values()),
        normalized_sha256,
        assemblage_path,
    )
    return dict(records_by_address)
