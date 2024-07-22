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
  },
  {
    label: 'Toolset',
    icon: 'pi pi-list',
    items: [
      {
        label: 'Capa',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/capa'
      },
      {
        label: 'Flare-Floss',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/flare-floss'
      },
      {
        label: 'Flare-VM',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/flare-vm'
      },
      {
        label: 'Flare-Fakenet-ng',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/flare-fakenet-ng'
      },
      {
        label: 'Ghidrathon',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/ghidrathon'
      },
      {
        label: 'dncil',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/dncil'
      },
      {
        label: 'GoReSym',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/GoReSym/'
      },
      {
        separator: true
      },
      {
        label: 'capa-rules',
        icon: 'pi pi-github',
        url: 'https://github.com/mandiant/capa-rules'
      }
    ]
  }
])
</script>

<template>
  <Menubar :model="items">
    <template #end>
      <div class="flex align-items-center gap-3">
        <a
          v-ripple
          href="https://github.com/mandiant/"
          class="flex align-items-center justify-content-center text-color w-2rem"
        >
          <i id="github-icon" class="pi pi-github text-2xl"></i>
        </a>
        <img src="../assets/images/icon.png" alt="Logo" class="w-2rem" />
      </div>
    </template>
    <template #item="{ item, props, hasSubmenu }">
      <a
        v-if="item.command"
        v-ripple
        v-bind="props.action"
        @click="item.command"
        class="flex align-items-center"
      >
        <span :class="item.icon" />
        <span class="ml-2">{{ item.label }}</span>
      </a>
      <a
        v-else
        v-ripple
        :href="item.url"
        :target="item.target"
        v-bind="props.action"
        class="flex align-items-center"
      >
        <span :class="item.icon" />
        <span class="ml-2">{{ item.label }}</span>
        <span v-if="hasSubmenu" class="pi pi-fw pi-angle-down ml-2" />
      </a>
    </template>
  </Menubar>
</template>
