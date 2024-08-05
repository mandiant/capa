<script setup>
import { ref } from 'vue'

import Menubar from 'primevue/menubar'

const items = ref([
  {
    label: 'Import Analysis',
    icon: 'pi pi-file-import',
    // TODO(s-ff): This is not the conventinal way of navigating to a new page.
    command: () => window.location.replace(window.location.origin + '/capa/') // reload the page
  }
])
</script>

<template>
  <Menubar :model="items" class="p-1">
    <template #end>
      <div class="flex align-items-center gap-3">
        <a
          v-ripple
          href="https://github.com/mandiant/capa"
          class="flex align-items-center justify-content-center text-color w-2rem"
        >
          <i id="github-icon" class="pi pi-github text-2xl"></i>
        </a>
        <img src="../assets/images/icon.png" alt="Logo" class="w-2rem" />
      </div>
    </template>
  </Menubar>
</template>
