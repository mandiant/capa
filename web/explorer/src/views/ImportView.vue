<template>
    <DescriptionPanel />
    <UploadOptions @load-from-local="loadFromLocal" @load-from-url="loadFromURL" />
</template>

<script setup>
import { watch } from "vue";

// componenets
import DescriptionPanel from "@/components/DescriptionPanel.vue";
import UploadOptions from "@/components/UploadOptions.vue";

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
