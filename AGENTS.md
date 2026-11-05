# AGENTS.md

- To set up the development environment, make sure that a venv is created and the pre-commit and pre-push hooks are installed, see `.pre-commit-config.yaml` and `doc/installation.md`.
- The `capa/` folder has the main functionality, `scripts/` has auxiliary plugins and scripts, and docs are in `doc/`.
- The default rules live in the `rules/` submodule ([capa-rules](https://github.com/mandiant/capa-rules)); do not add or edit rules in this repository.
- The tests live in the `tests/` folder, while test data and fixtures live in the `tests/data` submodule ([capa-testfiles](https://github.com/mandiant/capa-testfiles)); do not add or edit test data in this repository.
- All lints, formatters, and tests in `.github/workflows` **must** pass before making a PR. When applying linters or formatters locally, **ALWAYS use `pre-commit run <tool> --all-files`** (e.g., `pre-commit run ruff --all-files`). Do not run these tools directly (e.g., `ruff format <file>`), as doing so bypasses `.pre-commit-config.yaml` rules (such as 120-character line lengths) and will ruin existing codebase formatting.
- Add tests and a `CHANGELOG.md` entry for user-facing changes, as described in `.github/CONTRIBUTING.md`.
