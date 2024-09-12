# Development Guide for capa Explorer Web

This guide will help you set up the capa Explorer Web project for local development.

## Prerequisites

Before you begin, ensure you have the following installed:

-   Node.js (v20.x or later recommended)
-   npm (v10.x or later)
-   Git

## Setting Up the Development Environment

1. Clone the repository:

    ```
    git clone https://github.com/mandiat/capa.git
    cd capa/web/explorer
    ```

2. Install dependencies:

    ```
    npm install
    ```

3. Start the development server:

    ```
    npm run dev
    ```

    This will start the Vite development server. The application should now be running at `http://localhost:<port>`.

## Project Structure

```
web/exporer/
├── src/
│   ├── assets/
│   ├── components/
│   ├── composables/
│   ├── router/
│   ├── utils/
│   ├── views/
│   ├── App.vue
│   └── main.js
├── public/
├── tests/
├── index.html
├── package.json
├── vite.config.js
├── DEVELOPMENT.md
└── README.md
```

-   `src/`: Contains the source code of the application
-   `src/components/`: Reusable Vue components
-   `src/composables/`: Vue composition functions
-   `src/router/`: Vue Router configuration
-   `src/utils/`: Utility functions
-   `src/views/`: Top-level views/pages
-   `src/tests/`: Test files
-   `public/`: Static assets that will be served as-is

## Building for Production

To build the application for production:

```
npm run build
```

This will generate production-ready files in the `dist/` directory.

Or, you can build a standalone bundle application that can be used offline:

```
npm run build:bundle
```

This will generate an offline HTML bundle file in the `capa-explorer-web/` directory.

## Testing

Run the test suite with:

```
npm run test
```

We use Vitest as our testing framework. Please ensure all tests pass before submitting a pull request.

## Linting and Formatting

We use ESLint for linting and Prettier for code formatting. Run the linter with:

```
npm run lint
npm run format:check
npm run format
```

## Working with PrimeVue Components

capa Explorer Web uses the PrimeVue UI component library. When adding new features or modifying existing ones, refer to the [PrimeVue documentation](https://primevue.org/vite) for available components and their usage.

## Best Practices

1. Follow the [Vue.js Style Guide](https://vuejs.org/style-guide/) for consistent code style.
2. Document new functions, components, and complex logic.
3. Write tests for new features and bug fixes.
4. Keep components small and focused on a single responsibility.
5. Use composables for reusable logic across components.

## Additional Resources

-   [Vue.js Documentation](https://vuejs.org/guide/introduction.html)
-   [Vite Documentation](https://vitejs.dev/guide/)
-   [Vitest Documentation](https://vitest.dev/guide/)
-   [PrimeVue Documentation](https://www.primevue.org/)

If you encounter any issues or have questions about the development process, please open an issue on the GitHub repository.
