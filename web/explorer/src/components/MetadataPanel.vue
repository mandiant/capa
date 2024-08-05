<template>
    <!-- Main container with gradient background -->
    <div
        class="flex flex-column sm:flex-row align-items-stretch sm:align-items-center justify-content-between w-full p-3 shadow-1"
        :style="{ background: 'linear-gradient(to right, #2c3e50, #3498db)' }"
    >
        <!-- File information section -->
        <div class="flex-grow-1 mr-3 mb-3 sm:mb-0">
            <h1 class="text-xl m-0 text-overflow-ellipsis overflow-hidden white-space-nowrap text-white">
                {{ fileName }}
            </h1>
            <p class="text-xs mt-1 mb-0 text-white-alpha-70">
                SHA256:
                <a
                    :href="`https://www.virustotal.com/gui/file/${sha256}`"
                    target="_blank"
                    class="text-white-alpha-90 hover:text-white"
                    >{{ sha256 }}</a
                >
            </p>
        </div>

        <!-- Analysis information section  -->
        <div class="flex-grow-1 mr-3 mb-3 sm:mb-0">
            <!-- OS • Program Format • Arch -->
            <div class="flex flex-wrap align-items-center text-sm m-0 line-height-3 text-white">
                <span class="capitalize mr-2">{{ data.meta.analysis.os }}</span>
                <span class="sm:inline-block mx-2 text-white-alpha-30">•</span>
                <span class="uppercase mr-2">{{ data.meta.analysis.format }}</span>
                <span class="sm:inline-block mx-2 text-white-alpha-30">•</span>
                <span class="uppercase">{{ data.meta.analysis.arch }}</span>
            </div>
            <!-- Flavor • Extractor • CAPA Version • Timestamp -->
            <div class="flex flex-wrap align-items-center text-sm m-0 line-height-3 text-white">
                <span class="capitalize mr-1">{{ flavor }}</span>
                <span class="mr-1">analysis using</span>
                <span class="mr-2">{{ data.meta.analysis.extractor.split(/(Feature)?Extractor/)[0] }}</span>
                <span class="sm:inline-block mx-2 text-white-alpha-30">•</span>
                <span class="mr-2">CAPA v{{ data.meta.version }}</span>
                <span class="sm:inline-block mx-2 text-white-alpha-30">•</span>
                <span>{{ new Date(data.meta.timestamp).toLocaleString() }}</span>
            </div>
        </div>

        <!-- Key metrics section -->
        <div class="flex justify-content-around sm:justify-content-between flex-grow-1">
            <!-- Rules count -->
            <div class="text-center mr-3 sm:mr-0">
                <span class="block text-xl font-bold text-white">{{ keyMetrics.ruleCount }}</span>
                <span class="block text-xs uppercase text-white-alpha-70">Rules</span>
            </div>
            <!-- Namespaces count -->
            <div class="text-center mr-3 sm:mr-0">
                <span class="block text-xl font-bold text-white">{{ keyMetrics.namespaceCount }}</span>
                <span class="block text-xs uppercase text-white-alpha-70">Namespaces</span>
            </div>
            <!-- Functions or Processes count -->
            <div class="text-center">
                <span class="block text-xl font-bold text-white">{{ keyMetrics.functionOrProcessCount }}</span>
                <span class="block text-xs uppercase text-white-alpha-70">
                    {{ flavor === "static" ? "Functions" : "Processes" }}
                </span>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, onMounted } from "vue";

const props = defineProps({
    data: {
        type: Object,
        required: true
    }
});

const keyMetrics = ref({
    ruleCount: 0,
    namespaceCount: 0,
    functionOrProcessCount: 0
});

// get the filename from the path, e.g. "malware.exe" from "/home/user/malware.exe"
const fileName = props.data.meta.sample.path.split("/").pop();
// get the flavor from the metadata, e.g. "dynamic" or "static"
const flavor = props.data.meta.flavor;
// get the SHA256 hash from the metadata
const sha256 = props.data.meta.sample.sha256.toUpperCase();

// Function to parse metadata and update key metrics
const parseMetadata = () => {
    if (props.data) {
        keyMetrics.value = {
            ruleCount: Object.keys(props.data.rules).length,
            namespaceCount: new Set(Object.values(props.data.rules).map((rule) => rule.meta.namespace)).size,
            functionOrProcessCount:
                flavor === "static"
                    ? props.data.meta.analysis.feature_counts.functions.length
                    : props.data.meta.analysis.feature_counts.processes.length
        };
    }
};

// Call parseMetadata when the component is mounted
onMounted(() => {
    parseMetadata();
});
</script>
