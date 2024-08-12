<script setup>
import Menubar from "primevue/menubar";
</script>

<template>
    <Menubar class="p-1">
        <template #end>
            <div class="flex align-items-center gap-3">
                <a
                    v-ripple
                    v-tooltip.right="'Download capa Explorer Web for offline usage'"
                    href="/capa-explorer-web.zip"
                    download="capa-explorer-web.zip"
                    aria-label="Download capa Explorer Web release"
                >
                    <i class="pi pi-download text-xl"></i>
                </a>
                <a v-ripple href="https://github.com/mandiant/capa" class="flex justify-content-center w-2rem">
                    <i class="pi pi-github text-2xl"></i>
                </a>
                <img src="@/assets/images/icon.png" alt="Logo" class="w-2rem" />
            </div>
        </template>
    </Menubar>
</template>
