<!--
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

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
