<template>
    <div class="flex flex-column align-items-center mb-6">
        <div class="text-center">
            <h1>
                <img src="@/assets/images/logo-full.png" alt="Capa: identify program capabilities" />
                <h3 class="font-medium" style="color: rgb(37, 147, 215)">capa: identify program capabilities</h3>
            </h1>
        </div>
        <div>
            <p class="text-xl p-3 max-w-75rem" style="max-width: 75ch">
                capa Explorer Web is a web-based tool to explore the capabilities identified by capa. This tool allows
                you to interactively browse and display capa results in multiple viewing modes.
            </p>
        </div>
        <div class="bg-blue-50 border-round p-3 pb-4 text-center max-w-75rem mt-4">
            <p class="text-700 text-sm m-0">New to capa? Follow these quick steps to get started:</p>
            <p class="text-700 text-sm mb-3"></p>
            <ol class="text-left text-sm pl-4 mb-3">
                <li class="mb-2">
                    <a href="https://github.com/mandiant/capa/blob/master/doc/installation.md" class="underline">
                        Install capa
                    </a>
                    , e.g.
                    <ul>
                        <li>
                            download the latest
                            <a href="https://github.com/mandiant/capa/releases" class="underline">
                                standalone executable release
                            </a>
                        </li>
                        <li>
                            or run
                            <code>$ pip install flare-capa</code>
                        </li>
                    </ul>
                </li>
                <li class="mb-2">
                    Analyze a sample and save the JSON results:
                    <ul>
                        <li><code>$ capa -j /path/to/file > result.json</code></li>
                    </ul>
                </li>
                <li>Load the JSON results file into capa Explorer Web</li>
            </ol>
            <p class="text-700 text-sm m-0">
                For more detailed information, explore the
                <a
                    href="https://github.com/mandiant/capa/tree/master/web/explorer"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="underline"
                >
                    capa GitHub repository
                </a>
                .
            </p>
        </div>
        <div>
            <p class="text-base p-3 max-w-75rem">
                You can download capa Explorer Web for offline usage via the download button in the top-right corner of
                this page.
            </p>
        </div>
    </div>
</template>

<style scoped>
/* highlight inline code */
code {
    background-color: #e2e8f0;
    border-radius: 4px;
    font-family: monospace;
}
</style>
