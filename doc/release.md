# Release checklist

- [ ] Ensure all [milestoned issues/PRs](https://github.com/mandiant/capa/milestones) are addressed, or reassign to a new milestone.
- [ ] Add the `don't merge` label to all PRs that are close to be ready to merge (or merge them if they are ready) in [capa](https://github.com/mandiant/capa/pulls) and [capa-rules](https://github.com/mandiant/capa-rules/pulls).
- [ ] Ensure the [CI workflow succeeds in master](https://github.com/mandiant/capa/actions/workflows/tests.yml?query=branch%3Amaster).
- [ ] Ensure that `python scripts/lint.py rules/ --thorough` succeeds (only `missing examples` offenses are allowed in the nursery). You can [manually trigger a thorough lint](https://github.com/mandiant/capa-rules/actions/workflows/tests.yml) in CI via the "Run workflow" option. 
- [ ] Review changes
  - capa https://github.com/mandiant/capa/compare/\<last-release\>...master
  - capa-rules https://github.com/mandiant/capa-rules/compare/\<last-release>\...master
- [ ] Update [CHANGELOG.md](https://github.com/mandiant/capa/blob/master/CHANGELOG.md)
  - Do not forget to add a nice introduction thanking contributors
  - Remember that we need a major release if we introduce breaking changes
  - Sections: see template below
  - Update `Raw diffs` links
  - Create placeholder for `master (unreleased)` section
    ```
    ## master (unreleased)

    ### New Features

    ### Breaking Changes

    ### New Rules (0)

    -

    ### Bug Fixes

    ### capa explorer IDA Pro plugin

    ### Development

    ### Raw diffs
    - [capa <release>...master](https://github.com/mandiant/capa/compare/<release>...master)
    - [capa-rules <release>...master](https://github.com/mandiant/capa-rules/compare/<release>...master)
    ```
- [ ] Update [capa/version.py](https://github.com/mandiant/capa/blob/master/capa/version.py)
- [ ] Create a PR with the updated [CHANGELOG.md](https://github.com/mandiant/capa/blob/master/CHANGELOG.md) and [capa/version.py](https://github.com/mandiant/capa/blob/master/capa/version.py). Copy this checklist in the PR description.
- [ ] After PR review, merge the PR and [create the release in GH](https://github.com/mandiant/capa/releases/new) using text from the [CHANGELOG.md](https://github.com/mandiant/capa/blob/master/CHANGELOG.md).
- Verify GH actions
  - [ ] [upload artifacts](https://github.com/mandiant/capa/releases)
  - [ ] [publish to PyPI](https://pypi.org/project/flare-capa)
  - [ ] [create tag in capa rules](https://github.com/mandiant/capa-rules/tags)
  - [ ] [create release in capa rules](https://github.com/mandiant/capa-rules/releases)
- [ ] [Spread the word](https://twitter.com)
- [ ] Update internal service
