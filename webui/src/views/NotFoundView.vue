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
