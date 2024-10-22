import sys
import sqlite3
import argparse
from pathlib import Path
from dataclasses import dataclass

import pefile

import capa.main


@dataclass
class AssemblageRow:
    # from table: binaries
    binary_id: int
    file_name: str
    platform: str
    build_mode: str
    toolset_version: str
    github_url: str
    optimization: str
    repo_last_update: int
    size: int
    path: str
    license: str
    binary_hash: str
    repo_commit_hash: str
    # from table: functions
    function_id: int
    function_name: str
    function_hash: str
    top_comments: str
    source_codes: str
    prototype: str
    _source_file: str
    # from table: rvas
    rva_id: int
    start_rva: int
    end_rva: int

    @property
    def source_file(self):
        # cleanup some extra metadata provided by assemblage
        return self._source_file.partition(" (MD5: ")[0].partition(" (0x3: ")[0]


class Assemblage:
    conn: sqlite3.Connection
    samples: Path

    def __init__(self, db: Path, samples: Path):
        super().__init__()

        self.db = db
        self.samples = samples

        self.conn = sqlite3.connect(self.db)
        with self.conn:
            self.conn.executescript("""
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA busy_timeout = 5000;
                PRAGMA cache_size = -20000; -- 20MB
                PRAGMA foreign_keys = true;
                PRAGMA temp_store = memory;

                BEGIN IMMEDIATE TRANSACTION;
                CREATE INDEX IF NOT EXISTS idx__functions__binary_id ON functions (binary_id);
                CREATE INDEX IF NOT EXISTS idx__rvas__function_id ON rvas (function_id);

                CREATE VIEW IF NOT EXISTS assemblage AS 
                SELECT 
                    binaries.id AS binary_id,
                    binaries.file_name AS file_name,
                    binaries.platform AS platform,
                    binaries.build_mode AS build_mode,
                    binaries.toolset_version AS toolset_version,
                    binaries.github_url AS github_url,
                    binaries.optimization AS optimization,
                    binaries.repo_last_update AS repo_last_update,
                    binaries.size AS size,
                    binaries.path AS path,
                    binaries.license AS license,
                    binaries.hash AS hash,
                    binaries.repo_commit_hash AS repo_commit_hash,

                    functions.id AS function_id,
                    functions.name AS function_name,
                    functions.hash AS function_hash,
                    functions.top_comments AS top_comments,
                    functions.source_codes AS source_codes,
                    functions.prototype AS prototype,
                    functions.source_file AS source_file,

                    rvas.id AS rva_id,
                    rvas.start AS start_rva,
                    rvas.end AS end_rva
                FROM binaries 
                JOIN functions ON binaries.id = functions.binary_id
                JOIN rvas ON functions.id = rvas.function_id;
            """)

    def get_row_by_binary_id(self, binary_id: int) -> AssemblageRow:
        with self.conn:
            cur = self.conn.execute("SELECT * FROM assemblage WHERE binary_id = ? LIMIT 1;", (binary_id, ))
            return AssemblageRow(*cur.fetchone())

    def get_rows_by_binary_id(self, binary_id: int) -> AssemblageRow:
        with self.conn:
            cur = self.conn.execute("SELECT * FROM assemblage WHERE binary_id = ?;", (binary_id, ))
            row = cur.fetchone()
            while row:
                yield AssemblageRow(*row)
                row = cur.fetchone()

    def get_path_by_binary_id(self, binary_id: int) -> Path:
        with self.conn:
            cur = self.conn.execute("""SELECT path FROM assemblage WHERE binary_id = ? LIMIT 1""", (binary_id, ))
            return self.samples / cur.fetchone()[0]

    def get_pe_by_binary_id(self, binary_id: int) -> pefile.PE:
        path = self.get_path_by_binary_id(binary_id)
        return pefile.PE(data=path.read_bytes(), fast_load=True)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Inspect object boundaries in compiled programs")
    capa.main.install_common_args(parser, wanted={})
    parser.add_argument("assemblage_database", type=Path, help="path to Assemblage database")
    parser.add_argument("assemblage_directory", type=Path, help="path to Assemblage samples directory")
    parser.add_argument("binary_id", type=int, help="primary key of binary to inspect")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    if not args.assemblage_database.is_file():
        raise ValueError("database doesn't exist")

    db = Assemblage(args.assemblage_database, args.assemblage_directory)
    # print(db.get_row_by_binary_id(args.binary_id))
    # print(db.get_pe_by_binary_id(args.binary_id))

    @dataclass
    class Function:
        file: str
        name: str
        start_rva: int
        end_rva: int

    functions = [
        Function(
            file=m.source_file,
            name=m.function_name,
            start_rva=m.start_rva,
            end_rva=m.end_rva,
        )
        for m in db.get_rows_by_binary_id(args.binary_id)
    ]

    import rich
    import rich.table

    print(db.get_path_by_binary_id(args.binary_id))

    t = rich.table.Table()
    t.add_column("rva")
    t.add_column("filename")
    t.add_column("name")

    for function in sorted(functions, key=lambda f: f.start_rva):
        t.add_row(hex(function.start_rva), function.file, function.name)

    rich.print(t)

    # db.conn.close()

if __name__ == "__main__":
    sys.exit(main())
