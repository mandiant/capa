# Mandiant capa Python Style Guide

This style guide outlines the coding conventions and styling rules for the Mandiant capa project. It is designed to help Gemini Code Assist perform consistent code reviews that align with the project's existing conventions.

## Key Principles

- **Readability & Clarity**: Code must be readable and expressive. Names of variables, functions, and classes should clearly state their intent.
- **Performance & Optimization**: capa is a binary analysis tool; performance is critical. The matching engine is heavily optimized—avoid introducing matching overhead.
- **Type Safety**: Extensive type hinting is required to catch potential issues during development.
- **Rich Comments**: Code should explain *why* things are done, especially when dealing with OS-specific features, decompilers (IDA, Ghidra, BinNinja), or complex C-runtime interactions.

## Git Commit Messages

When committing changes, please adhere to the following style constraints:

- **Tense**: Use the present tense ("Add feature" not "Added feature").
- **Mood**: Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
- **Scope Prefix**: Prefix the first line of the commit message with the component/directory in question (e.g., rules: ..., render: ..., ida: ..., scripts: ...).
- **References**: Reference issues and pull requests liberally after the first line.

## Styling & Formatting Rules

### Line Length

- **Maximum line length**: **120** characters.

### Line Endings

- All text and code files **must use LF (Unix) line endings**. Do not use CRLF (Windows) endings (enforced via dos2unix).

### Imports Sorting

- Imports are grouped in the following order:
    1. Standard library imports
    2. Third-party imports (e.g., rich, msgspec)
    3. Local capa imports (e.g., capa.features..., capa.helpers)
- Imports within each group **must be sorted by line length** (increasing order), enforced by Ruff (length-sort = true in isort settings).

```python
import io
import os
import sys
import gzip
import ctypes
```

### Naming Conventions

- **Functions & Variables**: snake_case (e.g., `get_file_taste`, `is_runtime_ida`).
- **Classes**: CamelCase (e.g., `CapaProgressBar`, `PostfixColumn`).
- **Constants**: UPPER_CASE_WITH_UNDERSCORES (e.g., `FORMAT_PE`, `EXTENSIONS_DYNAMIC`).
- **Internal / Private**: Prefix with a single underscore `_` if internal to a class or module.

### Docstrings

- Use **triple double quotes (`"""`)** for all docstrings.
- Single-line docstrings are preferred for simple functions:
```python
def hex(n: int) -> str:
    """render the given number using upper case hex, like: 0x123ABC"""
```

- For complex methods/functions, use lowercase `args:` and `returns:` headings for arguments and return types:
```python
def is_cache_newer_than_rule_code(cache_dir: Path) -> bool:
    """
    basic check to prevent issues if the rules cache is older than relevant rules code

    args:
      cache_dir: the cache directory containing cache files

    returns:
      True if latest cache file is newer than relevant rule cache code
    """
```

### Copyright Header

Every python file must start with an Apache 2.0 copyright header. The copyright year should reflect the year of the file's creation (e.g., 2020 for core files, 2023, 2025 or 2026 for more recently added files). The header format must match `Copyright \d{4} Google LLC` (enforced by Ruff notice-rgx rule CPY001):

```python
# Copyright [YEAR] Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
```

### Specific Rule Deviations (Allowed Ignores)

Ruff is configured to ignore several strict rules to accommodate legacy patterns and formatting preferences:

- Line too long (E501) is ignored (rely on format auto-wrap up to 120).
- Bare excepts (E722) are allowed for legacy code, but handle specific exceptions in new code.
- Yoda conditions (SIM300) are allowed.
- Ternary operators (SIM108) are not strictly enforced over if-else statements.
- Implicit string concatenation is allowed over explicit (ISC003 ignored).
- Older syntax for type annotations (like `typing.Union` and `typing.Optional` instead of `X | Y` or `X | None`) is allowed to maintain backwards compatibility.

## Static Code Quality Rules (Ruff & Flake8 Plugins)

The project enforces strict code quality checks via Ruff. When statically reviewing Python files, you must verify that the code adheres to these specific checks:

- **No Print Statements (`T20`)**: Do not use `print()` or `pprint()` in core library code (e.g., inside `capa/`). Use the standard logging framework instead. *Exceptions*: allowed in `scripts/*`, `capa/main.py`, and `capa/features/extractors/binja/find_binja_api.py`.
- **Logging Format (`G`)**: Avoid using f-strings or `.format()` inside logging statements (e.g., `logger.info(f"error: {x}")`). Use lazy formatting to prevent unnecessary string construction overhead: `logger.info("error: %s", x)`.
- **Use Pathlib (`PTH`)**: Avoid legacy `os.path` or `os` filesystem operations (e.g., `os.path.exists()`, `os.path.join()`). Always use modern `pathlib.Path` equivalents (e.g., `Path.exists()`, the `/` operator).
- **Code Simplification (`SIM`, C4)**:
    - Avoid superfluous list/dict/set comprehensions when simpler built-ins exist (e.g., prefer `list(iterable)` over `[x for x in iterable]`).
    - Avoid unnecessary nested if statements that can be merged using `and`.
- **Mutable Default Arguments (`B006`)**: Never use mutable types (like lists `[]` or dicts `{}`) as default arguments in function definitions (e.g., `def foo(x=[])`). Use `None` as the default and initialize inside the function.
- **Accidental String Concatenation (`ISC`)**: Avoid implicit multi-line string concatenations unless explicitly intended (e.g. `x = "foo" "bar"`).
- **TODO Formatting (`TD`)**: Ensure TODO comments follow a consistent format, including the author's username/ID, e.g., `# TODO(username): describe task`.
- **Modern Python Syntax (`UP`)**: Enforce modern Python conventions where applicable (e.g., using standard `super()` instead of `super(Class, self)`).

## Contribution & Pull Requests

When proposing a Pull Request:

- **CHANGELOG**: You must update `CHANGELOG.md` under the master (unreleased) section for any bug fixes, new features, or breaking changes (unless no update is explicitly justified in the PR).
- **Tests & Docs**: Add corresponding tests and documentation for any code changes or new capabilities.
- **AI-Generated Code**: If you are using Gemini or another AI to assist with coding, you must explicitly disclose it in the PR template checklist and describe how it was used (prompts, model, and tool details).
