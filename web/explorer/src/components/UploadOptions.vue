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
    <div class="flex flex-wrap align-items-center justify-content-center gap-3 mb-6">
        <div class="flex-grow-1 flex align-items-center justify-content-center">
            <FileUpload
                mode="basic"
                name="model[]"
                accept=".json,.gz"
                :max-file-size="100000000"
                :auto="true"
                :custom-upload="true"
                choose-label="Upload from local"
                @uploader="$emit('load-from-local', $event)"
            />
        </div>

        <div class="hidden-mobile">
            <b>OR</b>
        </div>
        <Divider layout="horizontal" class="visible-mobile" align="center">
            <b>OR</b>
        </Divider>
        <div class="flex-grow-1 flex align-items-center justify-content-center gap-2">
            <FloatLabel>
                <InputText id="url" type="text" v-model="loadURL" />
                <label for="url">Load from URL</label>
            </FloatLabel>
            <Button icon="pi pi-arrow-right" @click="$emit('load-from-url', loadURL)" :disabled="!loadURL" />
        </div>
        <template v-if="!isBundle">
            <div class="hidden-mobile">
                <b>OR</b>
            </div>
            <Divider layout="horizontal" class="visible-mobile" align="center">
                <b>OR</b>
            </Divider>
            <div class="flex-grow-1 flex align-items-center justify-content-center">
                <Button label="Preview Static" @click="router.push({ path: '/', query: { rdoc: staticURL } })" />
            </div>

            <div class="hidden-mobile">
                <b>OR</b>
            </div>
            <Divider layout="horizontal" class="visible-mobile" align="center">
                <b>OR</b>
            </Divider>

            <div class="flex-grow-1 flex align-items-center justify-content-center">
                <Button label="Preview Dynamic" @click="router.push({ path: '/', query: { rdoc: dynamicURL } })" />
            </div>
        </template>
    </div>
</template>

<script setup>
import { ref } from "vue";
import FileUpload from "primevue/fileupload";
import Divider from "primevue/divider";
import FloatLabel from "primevue/floatlabel";
import InputText from "primevue/inputtext";
import Button from "primevue/button";

import { useRouter } from "vue-router";
const router = useRouter();

const loadURL = ref("");
const isBundle = import.meta.env.MODE === "bundle";

defineEmits(["load-from-local", "load-from-url"]);

const dynamicURL =
    "https://raw.githubusercontent.com/mandiant/capa-testfiles/master/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz";
const staticURL = "https://raw.githubusercontent.com/mandiant/capa-testfiles/master/rd/al-khaser_x64.exe_.json";
</script>

<style scoped>
@media screen and (min-width: 769px) {
    .hidden-mobile {
        display: flex !important;
    }
    .visible-mobile {
        display: none !important;
    }
}

@media screen and (max-width: 768px) {
    .hidden-mobile {
        display: none !important;
    }
    .visible-mobile {
        display: flex !important;
    }
}
</style>
