<template>
    <DescriptionPanel />
    <UploadOptions
        @load-from-local="loadFromLocal"
        @load-from-url="loadFromURL"
        @load-demo-static="loadDemoDataStatic"
        @load-demo-dynamic="loadDemoDataDynamic"
    />
</template>

<script setup>
import { watch } from "vue";

// componenets
import DescriptionPanel from "@/components/DescriptionPanel.vue";
import UploadOptions from "@/components/UploadOptions.vue";

// import demo data
import demoRdocStatic from "@testfiles/rd/al-khaser_x64.exe_.json";
import demoRdocDynamic from "@testfiles/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json";

// import router utils
import { useRouter, useRoute } from "vue-router";
const router = useRouter();
const route = useRoute();

// import rdoc loader function
import { useRdocLoader } from "@/composables/useRdocLoader";
const { loadRdoc } = useRdocLoader();

// import rdoc store
import { rdocStore } from "@/store/rdocStore";

const loadFromLocal = async (event) => {
    const result = await loadRdoc(event.files[0]);
    if (result) {
        rdocStore.setData(result);
        router.push("/analysis");
    }
};

const loadFromURL = async (url) => {
    const result = await loadRdoc(url);
    if (result) {
        rdocStore.setData(result);
        router.push({ name: "analysis", query: { rdoc: url } });
    }
};

const loadDemoDataStatic = async () => {
    const result = await loadRdoc(demoRdocStatic);
    if (result) {
        rdocStore.setData(demoRdocStatic);
        router.push("/analysis");
    }
};

const loadDemoDataDynamic = async () => {
    const result = await loadRdoc(demoRdocDynamic);
    if (result) {
        rdocStore.setData(demoRdocDynamic);
        router.push("/analysis");
    }
};

// Watch for changes in the rdoc query parameter
watch(
    () => route.query.rdoc,
    (rdocURL) => {
        if (rdocURL) {
            // Clear the query parameter
            router.replace({ query: {} });
            loadFromURL(decodeURIComponent(rdocURL));
        }
    },
    { immediate: true }
);
</script>
