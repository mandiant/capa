<script setup>
import { ref } from "vue";
import Menubar from "primevue/menubar";

const items = ref([
    {
        label: "Import Analysis",
        icon: "pi pi-file-import",
        command: () => {
            window.location.href = window.location.origin + "/capa/";
        }
    }
]);
</script>

<template>
    <Menubar :model="items" class="p-1">
        <div class="flex align-items-center gap-3">
            <a
                v-ripple
                href="https://github.com/mandiant/capa"
                target="_blank"
                rel="noopener noreferrer"
                class="flex align-items-center justify-content-center text-color w-2rem"
            >
                <i id="github-icon" class="pi pi-github text-2xl"></i>
            </a>
            <img src="../assets/images/icon.png" alt="Logo" class="w-2rem" />
        </div>
    </Menubar>
</template>
