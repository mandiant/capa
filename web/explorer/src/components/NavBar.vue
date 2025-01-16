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

<script setup>
import Menubar from "primevue/menubar";
import { RouterLink } from "vue-router";
import Button from "primevue/button";

const isBundle = import.meta.env.MODE === "bundle";
</script>

<template>
    <Menubar class="p-1">
        <template #start>
            <RouterLink to="/">
                <img src="@/assets/images/icon.png" alt="Logo" class="w-2rem" />
            </RouterLink>
        </template>
        <template #end>
            <div class="flex align-items-center gap-3">
                <a href="https://github.com/mandiant/capa/issues/new/choose" target="_blank" rel="noopener noreferrer">
                    <Button severity="contrast" size="small" outlined label="Provide feedback" />
                </a>
                <a
                    v-if="!isBundle"
                    v-ripple
                    v-tooltip.bottom="'Download capa Explorer Web for offline usage'"
                    href="capa-explorer-web.zip"
                    download="capa-explorer-web.zip"
                    aria-label="Download capa Explorer Web release"
                >
                    <i class="pi pi-download text-xl"></i>
                </a>
                <a v-ripple href="https://github.com/mandiant/capa" class="flex justify-content-center w-2rem">
                    <i class="pi pi-github text-2xl"></i>
                </a>
            </div>
        </template>
    </Menubar>
</template>
