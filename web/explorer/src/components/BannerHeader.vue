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
    <div
        v-if="showBanner"
        class="bg-bluegray-900 text-gray-100 flex justify-content-between lg:justify-content-center align-items-center flex-wrap"
    >
        <div class="font-bold mr-8">This is an early release</div>
        <div class="align-items-center hidden lg:flex">
            <span class="line-height-3">Please report any bugs, enhancements or features in the</span>
            <a
                v-ripple
                href="https://github.com/mandiant/capa/issues"
                class="flex align-items-center ml-2 mr-8 text-white"
            >
                <span class="no-underline font-bold">Github issues</span>
                <i class="pi pi-github ml-2"></i>
            </a>
        </div>
        <a
            v-ripple
            @click="closeBanner"
            class="flex align-items-center no-underline justify-content-center border-circle text-gray-50 hover:bg-bluegray-700 cursor-pointer transition-colors transition-duration-150"
            style="width: 2rem; height: 2rem"
        >
            <i class="pi pi-times"></i>
        </a>
    </div>
</template>

<script setup>
import { ref, onMounted } from "vue";

const showBanner = ref(true);

onMounted(() => {
    const bannerHidden = localStorage.getItem("bannerHidden");
    if (bannerHidden === "true") {
        showBanner.value = false;
    }
});

const closeBanner = () => {
    showBanner.value = false;
    localStorage.setItem("bannerHidden", "true");
};
</script>
