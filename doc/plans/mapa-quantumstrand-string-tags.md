# MAPA plan: vendor Quantum Strand string tags

This plan describes how to extend MAPA so every rendered `string:` line can carry right-aligned tags from Quantum Strand's string databases. The implementation target is broader than the earlier draft. It should include the full set of useful database-backed tags now: open-source library tags, CRT tags, expert tags, winapi tags, global-prevalence tags, and junk-code tags. The feature is still strictly limited to database matches. It must not import Quantum Strand or FLOSS as a runtime library, and it must not pull in Quantum Strand's whole-file layout analysis, structure tagging, file offsets, encoding columns, or any other non-database context.

The implementor should work only in `mapa/`, `tests/`, and packaging/docs as needed. Nothing belongs under `capa/`. The sibling checkout at `../quantumstrand/` is only a research source and a place to copy vendored resources from once.

## What MAPA should do when this lands

When MAPA emits a string referenced by a function, the left side should stay in the current MAPA style and the right side should show database-derived tags. The renderer should use Rich width calculations so the tag column stays visible and the string text is clipped first if necessary. The output should continue to be function-centric and concise.

A representative result looks like this:

```text
string:   "invalid distance code"                                                  #zlib
string:   "GetProcAddress"                                                   #winapi
string:   "!This program cannot be run in DOS mode."                           #common
string:   "CurrencyDispenser1"                                                   #capa
string:   "_initterm"                                                   #winapi #code-junk
```

The model should retain richer match metadata than the text renderer shows. The renderer only needs visible tags. The report model should still remember which database family matched and any associated metadata that might matter later.

## Non-goals

This feature is not a Quantum Strand port. Do not bring over its file-layout tree, structure labels like `import table`, section box rendering, code-vs-data analysis, duplicate-string tagging, relocation tagging, xor-decoding tags, or hidden-string filtering. Those features solve a different problem. MAPA already knows which function references a string and only needs database-backed context for that string.

MAPA should not start suppressing strings based on database matches. Even if an upstream expert rule has `action: hide`, MAPA should still render the string. Store the action in metadata if it exists, but do not use it to drop rows.

## Upstream resources to copy

All of the following resources should be vendored into MAPA under a new package such as `mapa/string_tags/data/`.

Library and CRT databases:

```bash
mkdir -p mapa/string_tags/data/oss mapa/string_tags/data/crt
cp ../quantumstrand/floss/qs/db/data/oss/*.jsonl.gz mapa/string_tags/data/oss/
cp ../quantumstrand/floss/qs/db/data/crt/msvc_v143.jsonl.gz mapa/string_tags/data/crt/
```

This copies these library databases:
`brotli.jsonl.gz`, `bzip2.jsonl.gz`, `cryptopp.jsonl.gz`, `curl.jsonl.gz`, `detours.jsonl.gz`, `jemalloc.jsonl.gz`, `jsoncpp.jsonl.gz`, `kcp.jsonl.gz`, `liblzma.jsonl.gz`, `libpcap.jsonl.gz`, `libsodium.jsonl.gz`, `mbedtls.jsonl.gz`, `openssl.jsonl.gz`, `sqlite3.jsonl.gz`, `tomcrypt.jsonl.gz`, `wolfssl.jsonl.gz`, `zlib.jsonl.gz`, plus the CRT database `msvc_v143.jsonl.gz`.

Expert, winapi, prevalence, and junk-code databases:

```bash
mkdir -p mapa/string_tags/data/expert mapa/string_tags/data/winapi mapa/string_tags/data/gp
cp ../quantumstrand/floss/qs/db/data/expert/capa.jsonl mapa/string_tags/data/expert/
cp ../quantumstrand/floss/qs/db/data/winapi/apis.txt.gz mapa/string_tags/data/winapi/
cp ../quantumstrand/floss/qs/db/data/winapi/dlls.txt.gz mapa/string_tags/data/winapi/
cp ../quantumstrand/floss/qs/db/data/gp/gp.jsonl.gz mapa/string_tags/data/gp/
cp ../quantumstrand/floss/qs/db/data/gp/cwindb-native.jsonl.gz mapa/string_tags/data/gp/
cp ../quantumstrand/floss/qs/db/data/gp/cwindb-dotnet.jsonl.gz mapa/string_tags/data/gp/
cp ../quantumstrand/floss/qs/db/data/gp/junk-code.jsonl.gz mapa/string_tags/data/gp/
cp ../quantumstrand/floss/qs/db/data/gp/xaa-hashes.bin mapa/string_tags/data/gp/
cp ../quantumstrand/floss/qs/db/data/gp/yaa-hashes.bin mapa/string_tags/data/gp/
```

The implementor should also create `mapa/string_tags/SOURCES.md` and record the upstream repo path, upstream commit, copied files, and any code copied or rewritten from upstream. The research for this plan used upstream commit `73eb1541e896c065fc694ba7b01067f56871631b`.

## Upstream code to read before implementing

The useful Quantum Strand code is small. Before writing anything, read `../quantumstrand/floss/qs/db/oss.py`, `expert.py`, `gp.py`, `winapi.py`, `../quantumstrand/floss/qs/main.py`, and the tests `../quantumstrand/tests/test_oss_db.py`, `test_winapi_db.py`, `test_gp_db.py`, `test_qs.py`, and `test_qs_pma0101.py`.

The only part of `floss/qs/main.py` that should influence MAPA design is the small tagging and Rich rendering logic. Leave the rest of that file behind.

## Behavior that must be preserved from Quantum Strand

Quantum Strand's database lookups are simple and should be preserved exactly.

The OSS and CRT databases are gzip-compressed JSONL files. Each line contains one `OpenSourceString` record with fields such as `string`, `library_name`, `library_version`, `file_path`, `function_name`, and `line_number`. Lookup is exact by `string`. A match emits tag `#<library_name>`. The CRT file uses `library_name: "msvc"`, so it emits `#msvc`.

The expert database file is plain `capa.jsonl`, not gzip-compressed despite what the readme says. Each record is an `ExpertRule` with `type`, `value`, `tag`, `action`, and descriptive metadata. Matching behavior follows `floss/qs/db/expert.py`: exact string match for `type == "string"`, substring search for `type == "substring"`, and `re.compile(rule.value).search(...)` for `type == "regex"`. A match emits `rule.tag`, which in the current vendored file is typically `#capa`.

The winapi database is two gzip-compressed text files. `dlls.txt.gz` is loaded into a lowercase set and matched against `string.lower()`. `apis.txt.gz` is loaded into a case-sensitive set and matched against the string verbatim. A match from either source emits `#winapi`.

The global-prevalence JSONL databases are `gp.jsonl.gz`, `cwindb-native.jsonl.gz`, and `cwindb-dotnet.jsonl.gz`. Quantum Strand loads them as `StringGlobalPrevalenceDatabase` and does exact string lookup. Any hit in any of those databases emits `#common`.

The junk-code JSONL database is `junk-code.jsonl.gz`. It has the same file format as the prevalence JSONL databases, but Quantum Strand treats it separately. Any hit emits `#code-junk`.

The hash databases are `xaa-hashes.bin` and `yaa-hashes.bin`. Each file is a flat sequence of 8-byte truncated MD5 digests. Quantum Strand computes `md5(string.encode("utf-8")).digest()[:8]` and checks membership in the set. A hit emits `#common`.

These match rules are the core of the feature. They are much more important than matching Quantum Strand's internal class names.

## Recommended MAPA package layout

Add a dedicated package under `mapa/`. A good layout is `mapa/string_tags/__init__.py`, `model.py`, `loaders.py`, `tagger.py`, a `data/` subtree, and `SOURCES.md`.

Do not copy upstream modules verbatim unless necessary. A MAPA-local rewrite is cleaner because the code is short and MAPA needs a narrower API than Quantum Strand.

`model.py` should define two small dataclasses. `StringTagMatch` should capture one concrete match with fields like `tag`, `source_family`, `source_name`, `kind`, and optional metadata such as `library_name`, `library_version`, `file_path`, `function_name`, `line_number`, `note`, `description`, `action`, `global_count`, `encoding`, and `location`. `StringTagResult` should hold the final sorted tag tuple plus the tuple of `StringTagMatch` entries.

`loaders.py` should own the file-format readers. It should use `gzip`, `hashlib`, `msgspec`, and `importlib.resources`. There is no reason to invent a new parser. This project already depends on `msgspec`, which is also what Quantum Strand uses for the JSONL formats.

`tagger.py` should own the process-wide cached tagger. A simple shape is `load_default_tagger()` plus an object with `tag_string(raw: str) -> StringTagResult`. The tagger should lazily load and cache the vendored databases once per process.

## Report-model changes

`mapa/model.py` should be extended so a rendered MAPA string can carry tags and match metadata. The minimal change is to add `tags` and `tag_matches` to `MapaString`. The existing `value` field should remain the display string. If the implementor wants to preserve the exact raw string too, add a `raw_value` field. That is worthwhile because MAPA currently trims trailing whitespace before storing the string, and exact-match databases should run against the untrimmed value.

The most important collector rule is this: match against the raw extracted string first, derive the display string second, and deduplicate on the display string only after the database matches have been computed. If two raw strings collapse to the same display value after `rstrip()`, their tags and metadata should be merged onto the single rendered `MapaString` entry.

## Collector guidance

The collector should keep its existing string-discovery behavior. This plan does not ask the implementor to revisit how MAPA follows data references or how it discovers a string in IDA. Once `collect_report()` recovers a raw string, the new tagging pipeline begins.

A good implementation sequence inside `mapa/collector.py` is: recover `raw_value`, call the vendored tagger on `raw_value`, compute `display_value = raw_value.rstrip()`, skip empty display values, and then either create or update the `MapaString` entry for that display value. The update path should union tag names and append only unique `StringTagMatch` values. The final `MapaString.tags` should be sorted for stable rendering and stable tests.

This is the one place where the current MAPA behavior is most likely to cause silent misses. If the implementor tags only the trimmed string, exact-match results from Quantum Strand can be lost.

## Tag aggregation rules

The model should preserve all concrete matches, even when multiple databases emit the same visible tag. This matters most for `#common`, because a string may hit several prevalence databases and one or both hash databases. The visible tag list should deduplicate tag names, but the metadata should preserve every source that contributed.

The tagger should produce tags in a deterministic order. A simple stable order is alphabetical order on the tag name after aggregation. The metadata order should also be deterministic, for example by `(tag, source_family, source_name, library_name, note, value)`.

## Rendering guidance

Replace the current plain markup string for `string:` rows with a dedicated Rich `Text` builder. The implementor should read `render_string()` and related helpers in `../quantumstrand/floss/qs/main.py` and copy only the layout idea. The left side is the existing `string:   "..."` text. The right side is the space-joined visible tag list. Width should come from Rich's own measurement.

A helper such as `Renderer.render_string_line(value: str, tags: Sequence[str]) -> Text` is sufficient. It should use `self.console.size.width - (self.indent * 2)` as the available width for the line content, build a `Text` object for the left side and another for the right side, reserve at least one separating space, and then align or truncate the left side so the right side stays visible. If the terminal is too narrow for that layout, fall back to a single-column form that still shows the tags.

MAPA should adopt one Quantum Strand display rule because it reduces noise without hiding information: when a string has `#common` plus one or more more-specific tags, omit `#common` from the visible tag column but keep it in `tag_matches` and `MapaString.tags`. That is a rendering choice only. The underlying data should stay intact.

No string row should be hidden by tag policy. `#common` and `#code-junk` may be styled in a muted color. `#capa` may be highlighted. `#winapi` and library tags can use the default string-tag style unless the implementor finds a better minimal palette. The important behavior is visibility and stable alignment. Decorative styling is secondary.

## Recommended visible-tag policy

The rendered tag column should follow these rules.

Show all tags except `#common` when a more-specific tag is also present. Keep `#common` visible only if it is the only tag. Show `#code-junk` even when other tags are present because it communicates a different kind of context than `#common`. Show `#winapi`, `#capa`, and library tags directly. Do not invent MAPA-specific aliases or rename the upstream tags.

This yields readable outputs such as `#winapi #code-junk`, `#capa`, `#zlib`, or `#common`. It avoids noisy combinations like `#common #winapi` on every common API name.

## Packaging guidance

If MAPA needs to work from an installed package, `pyproject.toml` will need changes because it currently only packages `capa*`. The implementor should include `mapa*` packages and package data under `mapa/string_tags/data/`. The loader should use `importlib.resources.files()` so it works both from a source checkout and an installed wheel.

Even if packaging is deferred, the code should still use `importlib.resources` because it centralizes the resource lookup and avoids hard-coded repository-relative paths.

## Implementation steps for the handoff

The implementor should start by copying the resources, writing `mapa/string_tags/SOURCES.md`, and adding pure loader tests before touching MAPA's collector or renderer. Then they should implement the small loader layer for the five upstream database families: OSS/CRT, expert, winapi, prevalence JSONL, and prevalence hash files. After that they should implement the aggregated tagger and add pure tagger tests using known literals from the vendored datasets.

Once the tagger is stable, they should extend `MapaString`, thread tagging through `mapa/collector.py`, and finally switch `mapa/renderer.py` to the Rich `Text`-based string-row helper. Only after all of that is working should they update packaging and installed-resource handling, because those changes are easier to verify when the core behavior already exists.

During implementation they should update `doc/plans/spec.md` and `doc/plans/design.md` to record the final user-visible behavior and the final module layout. The spec should say that `string:` rows may carry right-aligned database tags and should document the visible-tag policy. The design doc should say where the vendored databases live, how the loader is structured, and how the collector merges raw-string matches into deduplicated display strings.

## Concrete test plan

Most tests should avoid IDA. Start with pure loader and tagger tests. Known-good assertions from the upstream data include `"invalid distance code" -> #zlib`, `"IsolationAware function called after IsolationAwareCleanup" -> #msvc`, `"CurrencyDispenser1" -> #capa`, `"kernel32.dll" -> #winapi`, `"CreateFileA" -> #winapi`, and `"!This program cannot be run in DOS mode." -> #common`. `"_initterm"` is a useful mixed case because Quantum Strand's own tests show it as both `#winapi` and `#code-junk`.

Cover the expert database's three rule types: exact, substring, and regex. Add a hash-database test that emits `#common` even when the string is absent from the JSONL prevalence files. Add another case where several databases contribute the same visible tag and the metadata still records every contributing match.

Add renderer tests using a fixed-width Rich console. One test should show that an untagged string row still matches the old MAPA format. Another should show that a tagged row keeps the tag column at the right edge. A narrow-width test should show that the string side is clipped first. Another should check that `#common` disappears from the visible tag list when a more-specific tag exists while remaining present in the underlying model.

Finally, add report tests in `tests/test_mapa.py` that build a small `MapaReport` directly. At least one string should carry a library tag, at least one should carry `#common`, and at least one should carry a multi-tag combination like `#winapi #code-junk`. None of these tests should require IDA.

## Performance and memory notes

Vendoring every requested database is still practical, but loading them all eagerly may have a noticeable startup cost. The tagger should therefore be cached process-wide and built lazily. Hash files should be read once into memory as sets of 8-byte digests. The string databases should be decoded once into in-memory maps. This is a good place to keep the code simple first and optimize only if startup becomes a measured problem.

The current compressed data footprint is modest for OSS, CRT, expert, and winapi. The prevalence family is the largest part of the set, especially the hash files. That is another reason to centralize loading and avoid repeated per-function or per-string initialization.

## Notes the implementor should not miss

`floss/qs/db/data/expert/readme.md` says the expert database is gzip-compressed, but the shipped file is plain `capa.jsonl`. Follow the code and the actual file on disk. `floss/qs/db/oss.py` includes the CRT file in `DEFAULT_PATHS`, so treat `#msvc` as part of the library tagging feature. Quantum Strand's `remove_false_positive_lib_strings()` should not be copied because its five-hit threshold is tuned for whole-file triage and fits MAPA's per-function presentation poorly.

The main risk in this work is not the file formats. It is silent semantic drift during integration. The implementor should preserve Quantum Strand's exact query rules, tag against the raw string before trimming, keep all concrete matches in metadata, and only simplify at the renderer boundary.
