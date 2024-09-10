@isort:
    pre-commit run isort --show-diff-on-failure --all-files

@black:
    pre-commit run black --show-diff-on-failure --all-files

@ruff:
    pre-commit run ruff --all-files

@flake8:
    pre-commit run flake8 --hook-stage manual --all-files

@mypy:
    pre-commit run mypy --hook-stage manual --all-files

@deptry:
    pre-commit run deptry --hook-stage manual --all-files

@lint:
    -just isort
    -just black
    -just ruff
    -just flake8
    -just mypy
    -just deptry
