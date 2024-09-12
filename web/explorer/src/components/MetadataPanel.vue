<template>
    <!-- Main container with gradient background -->
    <div
        class="flex flex-wrap align-items-center justify-content-between w-full p-3 shadow-1"
        :style="{ background: 'linear-gradient(to right, #2c3e50, #3498db)' }"
    >
        <!-- File information section -->
        <div class="flex-grow-1 mr-3">
            <h1 class="text-xl m-0 text-white">
                {{ fileName }}
            </h1>
            <p class="text-xs mt-1 mb-0 text-white-alpha-70">
                SHA256:
                <a :href="`https://www.virustotal.com/gui/file/${sha256}`" target="_blank">{{ sha256 }}</a>
            </p>
        </div>

        <!-- Vertical divider -->
        <div class="mx-3 bg-white-alpha-30 hidden sm:block" style="width: 1px; height: 30px"></div>

        <!-- Analysis information section  -->
        <div class="flex-grow-1 mr-3">
            <!-- OS • Program Format • Arch -->
            <div class="flex align-items-center text-sm m-0 line-height-3 text-white">
                <span class="capitalize">{{ data.meta.analysis.os }}</span>
                <span class="ml-2 mr-2 text-white-alpha-30">•</span>
                <span class="uppercase">{{ data.meta.analysis.format }}</span>
                <span class="ml-2 mr-2 text-white-alpha-30">•</span>
                <span>{{ data.meta.analysis.arch === "i386" ? "i386" : data.meta.analysis.arch.toUpperCase() }}</span>
            </div>
            <!-- Flavor • Extractor • capa Version • Timestamp -->
            <div class="flex-wrap align-items-center text-sm m-0 line-height-3 text-white">
                <span class="capitalize">
                    {{ flavor }} analysis with {{ data.meta.analysis.extractor.split(/(Feature)?Extractor/)[0] }}
                </span>
                <!--- Extractor (e.g., CapeExtractor -> Cape, GhidraFeatureExtractor -> Ghidra, ... etc) -->
                <span class="mx-2 text-white-alpha-30">•</span>
                <span>capa v{{ data.meta.version }}</span>
                <span class="mx-2 text-white-alpha-30">•</span>
                <span>{{ new Date(data.meta.timestamp).toLocaleString() }}</span>
            </div>
        </div>

        <!-- Vertical divider -->
        <div class="mx-3 bg-white-alpha-30 hidden sm:block" style="width: 1px; height: 30px"></div>

        <!-- Key metrics section -->
        <div class="flex justify-content-around flex-grow-1">
            <!-- Rules count -->
            <div class="text-center">
                <span class="block text-xl font-bold text-white">{{ keyMetrics.ruleCount }}</span>
                <span class="block text-xs uppercase text-white-alpha-70">Rules</span>
            </div>
            <!-- Namespaces count -->
            <div class="text-center">
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

let keyMetrics = ref({
    ruleCount: 0,
    namespaceCount: 0,
    functionOrProcessCount: 0
});

// get the filename from the path, e.g. "malware.exe" from "/home/user/malware.exe"
const fileName = props.data.meta.sample.path.split("/").pop();
// get the flavor from the metadata, e.g. "dynamic" or "static"
const flavor = props.data.meta.flavor;
// get the SHA256 hash from the metadata
const sha256 = props.data.meta.sample.sha256;

// Function to parse metadata and update key metrics
const parseMetadata = () => {
    if (props.data) {
        keyMetrics.value = {
            ruleCount: Object.keys(props.data.rules).length,
            namespaceCount: new Set(Object.values(props.data.rules).map((rule) => rule.meta.namespace)).size,
            functionOrProcessCount:
                props.data.meta.analysis.feature_counts.functions?.length ||
                props.data.meta.analysis.feature_counts.processes?.length
        };
    }
};

// Call parseMetadata when the component is mounted
onMounted(() => {
    parseMetadata();
});
</script>
