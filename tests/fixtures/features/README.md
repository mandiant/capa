# backend feature fixtures

This spec describes how contributors should add and consume backend feature fixtures.

## Scope

This spec covers feature-fixture tests only. It does not cover extractor helper tests, CLI smoke tests, or other bespoke tests.

## Source of truth

Feature fixtures live in these JSON manifests under `tests/fixtures/features/`:

- `static.json`
- `binja-db.json`
- `binexport.json`
- `cape.json`
- `drakvuf.json`
- `vmray.json`

Each manifest contains:

- a `files` list that maps fixture keys to sample paths
- a `features` list that describes feature assertions

The loader reads all of these manifests and combines them into one fixture set.

A backend feature test should not maintain its own private list of feature fixtures if the same information can be expressed in these JSON manifests.

## Fixture shape

Each feature fixture specifies:

- the sample key
- the location within the sample
- the feature or statement to evaluate
- optional tags
- optional backend marks
- optional `expected: false`

If `expected` is omitted, it means `true`.

This applies to ordinary feature assertions and `count(...)` assertions.

Examples:

```json
{
  "file": "pma16-01",
  "location": "file",
  "feature": "format: pe"
}
```

```json
{
  "file": "mimikatz",
  "location": "function=0x40E5C2",
  "feature": "count(basic blocks): 7"
}
```

```json
{
  "file": "mimikatz",
  "location": "function=0x401000",
  "feature": "characteristic: loop",
  "expected": false
}
```

## Tags

Tags are used to describe fixture requirements or sample properties that backends may need for selection.

Examples include:

- `dotnet`
- `elf`
- `dynamic`
- `flirt`
- `binja-db`
- `binexport`
- `aarch64`

Tags may appear on file entries or feature entries. file tags are inherited by their features.

Tags should not duplicate information that can already be derived from:

- the location string
- the parsed feature type

Unknown tags should fail collection.

## Backend selection

Backends consume one shared fixture list and select the fixtures they support.

Large backends should prefer exclusion-based selection. this means new fixtures run by default unless they are explicitly out of scope.

Examples:

- `viv` excludes `.NET`
- `ghidra` excludes `.NET`
- `binja` excludes `.NET`
- `idalib` excludes `.NET`

Small-surface backends may use inclusion-based selection where that is clearer.

Examples:

- `dnfile` includes `.NET`
- `dotnetfile` includes `.NET`

Backends may also restrict supported scopes or feature types.

## Backend test file shape

A backend feature test file should normally have:

- one backend policy object
- one feature-test entry point that consumes shared fixtures

For example:

```python
import fixtures


@fixtures.parametrize_backend_feature_fixtures(
    fixtures.BackendFeaturePolicy(
        name="viv",
        include_tags={"static"},
        exclude_tags={"dotnet", "ghidra"},
    )
)
def test_viv_features(feature_fixture):
    extractor = fixtures.get_viv_extractor(feature_fixture.sample_path)
    fixtures.run_feature_fixture(extractor, feature_fixture)
```

Module-level availability checks are still allowed. runtime-specific hooks are allowed only when they depend on the installed backend or tool version and cannot be represented declaratively in the fixture manifests.

## Known bugs and marks

Known backend bugs should be represented in the fixture manifests through backend-specific marks.

Backends should not usually edit the shared JSON manifests just to avoid a fixture. they should prefer selecting or excluding fixtures through backend policy.

The main reason to keep marks in JSON is to record known exceptions such as:

- a backend-specific `xfail`
- a backend-specific `skip`

## Expected contributor workflow

When adding a new feature test:

1. add the sample path to the appropriate JSON manifest `files` list if it is not already present
2. add the feature fixture to that manifest `features` list
3. add tags only when they express a real requirement or sample property
4. omit `expected` unless the expected result is `false`
5. use JSON marks only for known backend bugs

When adding a new backend:

1. create one backend feature test file
2. define one backend policy describing extractor and exclusions
3. use the shared feature runner
4. add runtime hooks only if the environment or installed tool version requires them
