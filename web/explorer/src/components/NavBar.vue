<script setup>
import { ref } from "vue";
import Menubar from "primevue/menubar";
</script>

<template>
    <Menubar class="p-1">
        <template #end>
            <div class="flex align-items-center gap-3">
                <a
                    v-ripple
                    href="https://github.com/mandiant/capa"
                    class="flex align-items-center justify-content-center text-color w-2rem"
                >
                    <i id="gitsub-icon" class="pi pi-github text-2xl"></i>
                </a>
                <img src="@/assets/images/icon.png" alt="Logo" class="w-2rem" />
            </div>
        </template>
    </Menubar>
</template>
