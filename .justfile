@black:
    pre-commit run black --show-diff-on-failure --all-files

@ruff:
    pre-commit run ruff --all-files

@mypy:
    pre-commit run mypy --hook-stage manual --all-files

@deptry:
    pre-commit run deptry --hook-stage manual --all-files

@lint:
    -just black
    -just ruff
    -just mypy
    -just deptry
