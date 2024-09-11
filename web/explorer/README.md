# capa Explorer Web

capa Explorer Web is a browser-based user interface for exploring program capabilities identified by capa. It provides an intuitive and interactive way to analyze and visualize the results of capa analysis.

## Features

-   **Import capa Results**: Easily upload or import capa JSON result files.
-   **Interactive Tree View**: Explore and filter rule matches in a hierarchical structure.
-   **Function Capabilities**: Group and filter capabilities by function for static analysis.
-   **Process Capabilities**: Group capabilities by process for dynamic analysis.

## Getting Started

1. **Access the application**: Open capa Explorer Web in your web browser.
   You can start using capa Explorer Web by accessing [https://mandiant.github.io/capa](https://mandiant.github.io/capa/explorer) or running it locally by downloading the offline release from the top right-hand corner and opening it in your web browser.

2. **Import capa results**:

    - Click on "Upload from local" to select a capa analysis document file from your computer (with a version higher than 7.0.0).
        - You can generate the analysis document by running `capa.exe -j results.json sample.exe_`
    - Or, paste a URL to a capa JSON file and click the arrow button to load it.
        - Like for the other import mechanisms, loading of both plain (`.json`) and GZIP compressed JSON (`.json.gz`) files is supported).
    - Alternatively, use the "Preview Static" or "Preview Dynamic" for sample data.

3. **Explore the results**:

    - Use the tree view to navigate through the identified capabilities.
    - Toggle between different views using the checkboxes in the settings panel:
        - "Show capabilities by function/process" for grouped analysis.
        - "Show distinct library rule matches" to include or exclude library rules.
        - "Show columns filters" to show per-column search filters.

4. **Interact with the results**:
    - Expand/collapse nodes in the table to see more details by clicking rows or clicking arrow icons.
    - Use the search and filter options to find specific features, functions or capabilities (rules).
    - Right click on rule names (and `match` nodes) to view their source code or additional information.

## Feedback and Contributions

We welcome your feedback and contributions to improve the web-based capa explorer. Please report any issues or suggest enhancements through the `capa` GitHub repository.

---

For developers interested in building or contributing to capa Explorer Web, please refer to our [Development Guide](DEVELOPMENT.md).
