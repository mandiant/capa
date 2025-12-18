# Ghidra support

capa supports using Ghidra (via [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)) as a feature extraction backend. This allows you to run capa against binaries using Ghidra's analysis engine.

## prerequisites

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) >= 12.0 must be installed and available via the `GHIDRA_INSTALL_DIR` environment variable.

## installation

### standalone binary (recommended)

The standalone binary is the preferred way to run capa with the Ghidra backend.
Although the binary does not bundle the Java environment or Ghidra itself, it will dynamically load them at runtime.

### python package

To use the Ghidra backend, install `flare-capa` with the `ghidra` extra. This ensures PyGhidra and other necessary dependencies are installed.

```bash
pip install "flare-capa[ghidra]"
```

## usage

To use the Ghidra backend, specify it with the `-b` or `--backend` flag:

```bash
capa -b ghidra /path/to/sample
```

capa will:
1.  Initialize a headless Ghidra instance.
2.  Create a temporary project.
3.  Import and analyze the sample.
4.  Extract features and match rules.
5.  Clean up the temporary project.

**Note:** The first time you run this, it may take a few moments to initialize the Ghidra environment.
