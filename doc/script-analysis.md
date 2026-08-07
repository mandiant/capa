# Script Analysis (Tree-Sitter)

Script analysis extends capa to support the analysis of script-based files which includes Python(.py), C#(.cs), template languages such as ASPX and HTML (.aspx, .html) and Bash(.sh). It uses [Tree-sitter](https://tree-sitter.github.io/tree-sitter/), an incremental parsing library that generates a concrete syntax tree(CST).

The Tree-sitter extractor walks the syntax tree, extracts semantic features such as imported modules, instantiated classes called APIs, string literals, properties and matches them against the existing capa rule set. Script analysis uses the same rule engine and output pipeline as binary analysis.

## Supported languages

| Language     | File Extension(s)   | Description                                |
|------------- |-------------------- |--------------------------------------------|
| Python       | `.py`               | Python scripts                             |
| C#           | `.cs`               | C# source files                            |
| HTML / ASPX  | `.html`, `.aspx`    | HTML templates with embedded server-side code |
| Bash         | `.sh`               | Bash shell scripts                         |  

## Workflow  

Script analysis introduces the `FORMAT_SCRIPT` file format alongside `FORMAT_PE`, `FORMAT_ELF` and `FORMAT_DOTNET`. Once a file is identified as a script, capa routes analysis through the Tree-sitter extractor. Rule matching and result rendering are identical to binary analysis.  

1. **Detect the source language** using either extension-based or content-based detection.
2. **Parse the source** into a Tree-sitter syntax tree.
3. **Extract semantic features** such as imports, classes, function calls, properties, and strings.
4. **Map extracted symbols** using language-specific signature files.
5. **Evaluate capa rules** against the extracted features.

## Embedded Templates  

Some file formats embed one language inside another. For example, an ASPX page can contain HTML along with embedded C# or VB.NET code blocks (`<% ... %>`).

Template files are first parsed using the outer language grammar to identify embedded code blocks. These blocks are then parsed using the appropriate grammar for the embedded language, allowing features to be extracted from both the outer and embedded layers.

## Repository layout

Tree-sitter extraction lives under:

```
capa/features/extractors/ts/
├── autodetect.py      # language detection
├── engine.py          # Tree-sitter query engine
├── tools.py           # shared parsing helpers
└── signatures/
    ├── cs.json
    ├── py.json
    ├── sh.json
    └── ...
```

## Signature files

Each supported language provides a signature file under
`capa/features/extractors/ts/signatures/`.

Signature files map language-specific symbols to capa features.

Example:

```json
{
  "classes": [
    "socket.socket",
    "subprocess.Popen"
  ]
}
```

## Usage  

Script analysis is invoked the same way as binary analysis.

```console
$ capa sample.py
$ capa script.sh
$ capa webshell.aspx
```

## Testing

Tree-sitter tests live in `tests/test_ts.py`.

Representative source samples are maintained in the `capa-testfiles` repository.  

## Installation

Script analysis can currently be used by installing capa from the source code or by building a standalone binary using PyInstaller. See [Method 3: Inspecting the capa source code](installation.md#method-3-inspecting-the-capa-source-code) for instructions.

It will also be available through the official standalone binaries and the Python package installed with `pip` in an upcoming capa release.

## Contributing Guidelines

When adding support for a new language or extending support for an existing language, consider the following:

1. **Add dependencies and detection:** Add the required Tree-sitter runtime and language grammar packages to `requirements.txt` and `pyproject.toml`, and update language detection to recognize the new language and its file extensions.

2. **Add extraction support:** Implement the required Tree-sitter parsing and feature extraction logic for the language.

3. **Add signatures and rules:** Add a language-specific signature file under `capa/features/extractors/ts/signatures/` and add or update capa rules in the `capa-rules` repository to match the extracted features and capabilities.

4. **Add test samples:** Add source samples to the [`capa-testfiles`](https://github.com/mandiant/capa-testfiles) repository and corresponding tests in the `capa` repository.

5. **Run the tests:** Run the relevant Tree-sitter tests and verify that the expected features and capabilities are extracted from the samples.
