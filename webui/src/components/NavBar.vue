<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import Menubar from 'primevue/menubar'

const router = useRouter()

const items = ref([
  {
    label: 'Import Analysis',
    icon: 'pi pi-file-import',
    command: () => {
      router.push('/')
      // Force a route change even if we're already on the home page
      // we need to this to force the page to reload
      router.go(0)
    }
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