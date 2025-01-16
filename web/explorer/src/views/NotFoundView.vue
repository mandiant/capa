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
    <div class="flex flex-column align-items-center justify-content-center min-h-screen bg-blue-50">
        <h1 class="text-900 font-bold text-8xl mb-4">404</h1>
        <p class="text-600 text-3xl mb-5">Oops! The page you're looking for doesn't exist.</p>

        <Button label="Go Home" icon="pi pi-home" @click="goHome" />
    </div>
</template>

<script setup>
import { useRouter } from "vue-router";
import Button from "primevue/button";

const router = useRouter();

const goHome = () => {
    router.push("/");
};
</script>
