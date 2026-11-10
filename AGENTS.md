# AGENTS.md

Read `.github/CONTRIBUTING.md` first. If expected behavior or design is unclear, ask before implementing.

## 1. Understand the context
- Read the issue, linked PRs, and prior reviews. Understand why the problem remains unsolved before implementing.
- Do not implement an old TODO without understanding its original context.

## 2. Keep the scope tight
- Keep each PR focused on the issue being addressed. Move unrelated cleanup and independent improvements into separate PRs.

## 3. Design decisions
- No speculative public APIs, CLI options, or abstract methods. Require a concrete use case, caller, and test.
- Discuss additions or changes to public APIs, public signatures, and release artifacts with maintainers. Deprecate public interfaces before removal; coordinate breaking changes with major releases.

## 4. Implementation quality
- Reuse existing helpers instead of duplicating them.
- Preserve function contracts; do not silently return `None` where a value is required.
- Catch specific exceptions where possible. Do not swallow unexpected exceptions.
- Annotate changed Python code and keep mypy passing.

## 5. Testing
- Tests for behavior changes should verify the expected behavior, not merely execute the code.
- Assert emitted serialization keys and structure. Round-trip tests alone can hide incorrect output.
- Use `xfail` with a reason for known backend gaps. Do not remove or silently skip failing tests to make CI pass.
- For focused unit tests, use small, hard-coded rule sets or curated fixtures rather than the live rule corpus.

## 6. Repository workflow
- `rules/` (capa-rules) and `tests/data` (capa-testfiles) are submodules. Make rule changes in capa-rules, not here.
- New test binaries or shared data: open and merge a capa-testfiles PR first, then update the `tests/data` pointer in capa.
- Run linters and formatters with `pre-commit run <tool> --all-files` (e.g. `pre-commit run ruff --all-files`), not directly. Direct runs bypass `.pre-commit-config.yaml` settings.

## 7. Rules: precise and domain-specific
- Non-nursery rules need a real-world example. Do not fabricate binaries. No suitable example: remove `examples` and use `nursery/`.
- Use the smallest reasonable scope. Do not tune `count()` or feature combinations to one sample.
- Rule logic changes need representative samples or references.
- Run `python ../scripts/lint.py --thorough -t "<rule name>" -v .` in capa-rules before review.

## 8. Compatibility and regressions
- Changing a serialized JSON key is a schema migration. Check freeze files, result documents, the web explorer, tests, and external consumers, and coordinate with maintainers.
- Keep serialization logic in the serializer, not in core feature types.
- Bump `CURRENT_VERSION` only when freeze format semantics change; regenerate snapshots for output changes that do not alter the format's meaning.
- `enable_cache=False` must not read, write, or create `cache_dir`. Treat stale or malformed cache entries as misses.

## 9. Collaborate with humans
- State assumptions and design trade-offs. Flag decisions that need maintainer input before implementing.

## 10. Before requesting review
- Run relevant tests, linters, and formatters. All applicable checks in .github/workflows must pass.
- Add tests and a `CHANGELOG.md` entry for user-facing changes, or the no-change waiver in the PR template.
- Disclose AI assistance in the PR template.
- Summarize what was tested, what was not, and known limitations.