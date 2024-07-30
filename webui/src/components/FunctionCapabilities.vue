<template>
  <div>
    <DataTable
      :value="tableData"
      rowGroupMode="rowspan"
      groupRowsBy="funcaddr"
      sortMode="single"
      removableSort
      size="small"
      :filters="filters"
      :rowHover="true"
      :filterMode="filterMode"
      filterDisplay="menu"
      :globalFilterFields="['funcaddr', 'ruleName', 'namespace']"
    >
      <template #header>
        <InputText v-model="filters['global'].value" placeholder="Global Search" />
      </template>

      <Column field="funcaddr" sortable header="Function Address" :rowspan="3" class="w-min">
        <template #body="slotProps">
          <span style="font-family: monospace">{{ slotProps.data.funcaddr }}</span>
          <span v-if="slotProps.data.matchCount > 1" class="font-italic">
            ({{ slotProps.data.matchCount }} matches)
          </span>
        </template>
      </Column>

      <Column field="ruleName" header="Matches" class="w-min">
        <template #body="slotProps">
          {{ slotProps.data.ruleName }}
          <LibraryTag v-if="slotProps.data.lib" />
        </template>
      </Column>

      <Column field="namespace" header="Namespace"></Column>
    </DataTable>

    <Dialog v-model:visible="sourceDialogVisible" :style="{ width: '50vw' }">
      <highlightjs lang="yml" :code="currentSource" class="bg-white" />
    </Dialog>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Dialog from 'primevue/dialog'
import LibraryTag from './misc/LibraryTag.vue'
import InputText from 'primevue/inputtext'

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

const filters = ref({
  global: { value: null, matchMode: 'contains' }
})
const filterMode = ref('lenient')
const sourceDialogVisible = ref(false)
const currentSource = ref('')

const showSource = (source) => {
  currentSource.value = source
  sourceDialogVisible.value = true
}

import { parseFunctionCapabilities } from '../utils/rdocParser'

const tableData = computed(() => parseFunctionCapabilities(props.data, props.showLibraryRules))
</script>

<style scoped>
/* tighten up the spacing between rows */
:deep(.p-datatable.p-datatable-sm .p-datatable-tbody > tr > td) {
  padding: 0.1rem 0.5rem !important;
}
</style>
