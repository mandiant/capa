<template>
    <div class="flex flex-column align-items-center mb-6">
        <div class="text-center">
            <h1>
                <img src="@/assets/images/logo-full.png" alt="Capa: identify program capabilities" />
                <h3 class="font-medium" style="color: rgb(176, 26, 26)">capa: identify program capabilities</h3>
            </h1>
        </div>
        <div>
            <p class="text-xl p-3 max-w-75rem" style="max-width: 75ch">
                capa explorer web is a web-based tool for exploring the capabilities identified in a program. It can be
                used to search and display the rule matches in different viewing modes.
            </p>
        </div>
        <div class="bg-blue-50 border-round p-3 pb-4 text-center max-w-75rem mt-4">
            <p class="text-700 text-sm m-0">New to capa? Follow these quick steps to get started:</p>
            <p class="text-700 text-sm mb-3"></p>
            <ol class="text-left text-sm pl-4 mb-3">
                <li class="mb-2">Install capa: <code>pip install flare-capa</code></li>
                <li class="mb-2">Generate JSON output: <code>capa -j /path/to/file > result.json</code></li>
                <li>Upload the JSON file here to explore the results</li>
            </ol>
            <p class="text-700 text-sm m-0">
                For more detailed information, explore the
                <a
                    href="https://github.com/mandiant/capa"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-blue-600 hover:text-blue-800 transition-colors duration-200"
                >
                    capa GitHub repository</a
                >.
            </p>
        </div>
    </div>
</template>

<style scoped>
/* highlight inline code */
code {
    background-color: #e2e8f0;
    padding: 2px 4px;
    border-radius: 4px;
    font-family: monospace;
}
</style>
