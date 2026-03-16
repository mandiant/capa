from __future__ import annotations

import logging

from mapa.string_tags.model import StringTagMatch, StringTagResult
from mapa.string_tags.loaders import (
    GpHashDatabase,
    GpJsonlDatabase,
    OssDatabase,
    ExpertDatabase,
    WinapiDatabase,
    load_expert_database,
    load_gp_hash_databases,
    load_gp_jsonl_databases,
    load_junk_code_database,
    load_oss_databases,
    load_winapi_database,
)

logger = logging.getLogger(__name__)


class StringTagger:
    def __init__(
        self,
        oss_dbs: list[OssDatabase],
        expert_db: ExpertDatabase,
        winapi_db: WinapiDatabase,
        gp_jsonl_dbs: list[GpJsonlDatabase],
        gp_hash_dbs: list[GpHashDatabase],
        junk_code_db: GpJsonlDatabase,
    ):
        self.oss_dbs = oss_dbs
        self.expert_db = expert_db
        self.winapi_db = winapi_db
        self.gp_jsonl_dbs = gp_jsonl_dbs
        self.gp_hash_dbs = gp_hash_dbs
        self.junk_code_db = junk_code_db

    def tag_string(self, raw: str) -> StringTagResult:
        matches: list[StringTagMatch] = []

        for db in self.oss_dbs:
            hit = db.query(raw)
            if hit is not None:
                matches.append(StringTagMatch(
                    tag=f"#{hit.library_name}",
                    source_family="oss",
                    source_name=hit.library_name,
                    kind="exact",
                    library_name=hit.library_name,
                    library_version=hit.library_version,
                    file_path=hit.file_path or "",
                    function_name=hit.function_name or "",
                    line_number=hit.line_number,
                ))

        for rule in self.expert_db.query(raw):
            matches.append(StringTagMatch(
                tag=rule.tag,
                source_family="expert",
                source_name="capa",
                kind=rule.type,
                note=rule.note,
                description=rule.description,
                action=rule.action,
            ))

        if self.winapi_db.query(raw):
            matches.append(StringTagMatch(
                tag="#winapi",
                source_family="winapi",
                source_name="winapi",
                kind="exact",
            ))

        for db in self.gp_jsonl_dbs:
            entries = db.query(raw)
            if entries:
                for entry in entries:
                    matches.append(StringTagMatch(
                        tag="#common",
                        source_family="gp",
                        source_name="jsonl",
                        kind="exact",
                        global_count=entry.global_count,
                        encoding=entry.encoding,
                        location=entry.location or "",
                    ))

        for db in self.gp_hash_dbs:
            if db.query(raw):
                matches.append(StringTagMatch(
                    tag="#common",
                    source_family="gp",
                    source_name="hash",
                    kind="hash",
                ))

        if self.junk_code_db.query(raw):
            matches.append(StringTagMatch(
                tag="#code-junk",
                source_family="gp",
                source_name="junk-code",
                kind="exact",
            ))

        if not matches:
            return StringTagResult.empty()

        tags = sorted(set(m.tag for m in matches))
        matches.sort(key=lambda m: m.sort_key)
        return StringTagResult(tags=tuple(tags), matches=tuple(matches))


_cached_tagger: StringTagger | None = None


def load_default_tagger() -> StringTagger:
    global _cached_tagger
    if _cached_tagger is not None:
        return _cached_tagger

    logger.debug("loading string tag databases...")
    tagger = StringTagger(
        oss_dbs=load_oss_databases(),
        expert_db=load_expert_database(),
        winapi_db=load_winapi_database(),
        gp_jsonl_dbs=load_gp_jsonl_databases(),
        gp_hash_dbs=load_gp_hash_databases(),
        junk_code_db=load_junk_code_database(),
    )
    _cached_tagger = tagger
    logger.debug("string tag databases loaded")
    return tagger
