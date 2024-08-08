# Capa Explorer Web

Capa Explorer WebUI is a web-based user interface for exploring program capabilities identified by the capa tool. It provides an intuitive and interactive way to analyze and visualize the results of capa analysis.

## Features

-   **Import capa Results**: Easily upload or import capa JSON result files.
-   **Interactive Tree View**: Explore and filter rule matches in a hierarchical structure.
-   **Function Capabilities**: Group and filter capabilities by function for static analysis.
-   **Process Capabilities**: Group capabilities by process for dynamic analysis.

## Getting Started

1. **Access the Application**: Open the Capa Explorer WebUI in your web browser.
   You can start using Capa Explorer Web by accessing [https://mandiant.github.io/capa](https://mandiant.github.io/capa/) or running it locally by dowloading the offline release in the [releases](https://github.com/mandiant/capa/releases) section and loading it in your browser.

2. **Import capa Results**:

    - Click on "Upload from local" to select a capa analysis document file from your computer (with a version higher than 7.0.0).
    - Or, paste a URL to a capa JSON file and click the arrow button to load it.
    - Alternatively, use the "Preview Static" or "Preview Dynamic" for sample data.

3. **Explore the Results**:

    - Use the tree view to navigate through the identified capabilities.
    - Toggle between different views using the checkboxes in the settings panel:
        - "Show capabilities by function/process" for grouped analysis.
        - "Show library rule matches" to include or exclude library rules.

4. **Interact with the Data**:
    - Expand/collapse nodes in the table to see more details.
    - Use the search and filter options to find specific features, functions or capabilities (rules).
    - Right click on rule names to view their source code or additional information.

## Feedback and Contributions

We welcome your feedback and contributions to improve the web-based Capa Explorer. Please report any issues or suggest enhancements through the `capa` GitHub repository.

---

For developers interested in building or contributing to Capa Explorer WebUI, please refer to our [Development Guide](DEVELOPMENT.md).
