<template>
  <TreeTable
    :value="treeData"
    v-model:expandedKeys="expandedKeys"
    size="small"
    :filters="filters"
    :filterMode="filterMode.value"
    sortField="funcaddr"
    :sortOrder="1"
    removableSort
    :indentation="1.3"
  >
    <template #header>
      <div class="flex justify-content-between align-items-center mb-4 mx-2">
        <Button icon="pi pi-expand" @click="toggleAll" label="Toggle All" class="mr-3" />
        <IconField>
          <InputIcon class="pi pi-search" />
          <InputText v-model="filters['global']" placeholder="Global search" />
        </IconField>
      </div>
    </template>

    <Column field="funcaddr" sortable header="Function Address" expander filterMatchMode="contains">
      <template #filter>
        <InputText
          style="width: 70%"
          v-model="filters['funcaddr']"
          type="text"
          placeholder="Filter by function address"
        />
      </template>
      <template #body="slotProps">
        {{ slotProps.node.data.funcaddr }}
        <span v-if="slotProps.node.data.matchcount > 1" class="font-italic"
          >({{ slotProps.node.data.matchcount }} matches)</span
        >
        <Tag
          v-if="slotProps.node.data.lib"
          class="ml-2"
          style="scale: 0.8"
          v-tooltip.top="{
            value: 'Library rules capture common logic',
            showDelay: 100,
            hideDelay: 100
          }"
          value="lib"
          severity="info"
        ></Tag>
      </template>
    </Column>

    <Column field="namespace" sortable header="Namespace" filterMatchMode="contains">
      <template #filter>
        <InputText v-model="filters['namespace']" type="text" placeholder="Filter by namespace" />
      </template>
    </Column>

    <Column field="source" header="Source">
      <template #body="slotProps">
        <Button
          v-if="slotProps.node.data.source"
          rounded
          icon="pi pi-external-link"
          size="small"
          severity="secondary"
          style="height: 1.5rem; width: 1.5rem"
          @click="showSource(slotProps.node.data.source)"
        />
      </template>
    </Column>
  </TreeTable>

  <Dialog v-model:visible="sourceDialogVisible" :style="{ width: '50vw' }">
    <highlightjs lang="yml" :code="currentSource" />
  </Dialog>
</template>

<script setup>
import { ref, computed } from 'vue'
import TreeTable from 'primevue/treetable'
import Column from 'primevue/column'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import Badge from 'primevue/badge'
import Tag from 'primevue/tag'
import InputText from 'primevue/inputtext'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'

const props = defineProps({
  data: {
    type: Object,
    required: true
  },
  showLibraryRules: {
    type: Boolean,
    default: false
  }
})

const filters = ref({})
const filterMode = ref({ value: 'lenient' })
const sourceDialogVisible = ref(false)
const currentSource = ref('')
const expandedKeys = ref({})

const showSource = (source) => {
  currentSource.value = source
  sourceDialogVisible.value = true
}

const toggleAll = () => {
  let _expandedKeys = {}

  if (Object.keys(expandedKeys.value).length === 0) {
    const expandAll = (node) => {
      if (node.children && node.children.length) {
        _expandedKeys[node.key] = true
        node.children.forEach(expandAll)
      }
    }

    treeData.value.forEach(expandAll)
  }

  expandedKeys.value = _expandedKeys
}

import { parseFunctionCapabilities } from '../utils/rdocParser'

const treeData = computed(() => parseFunctionCapabilities(props.data, props.showLibraryRules))
</script>
