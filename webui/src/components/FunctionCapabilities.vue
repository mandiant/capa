<template>
  <div>
    <DataTable
      :value="tableData"
      rowGroupMode="rowspan"
      groupRowsBy="funcaddr"
      sortMode="single"
      removableSort
      size="small"
      :sortOrder="1"
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
          {{ slotProps.data.funcaddr }}
          <span v-if="slotProps.data.matchcount > 1" class="font-italic">
            ({{ slotProps.data.matchcount }} matches)
          </span>
        </template>
      </Column>

      <Column field="ruleName" sortable header="Matches" class="w-min">
        <template #body="slotProps">
          {{ slotProps.data.ruleName }}
          <LibraryTag
            v-if="slotProps.data.lib"
            />
        </template>
      </Column>

      <Column field="namespace" sortable header="Namespace"></Column>

      <Column field="source" header="Source">
        <template #body="slotProps">
          <Button
            v-if="slotProps.data.source"
            rounded
            icon="pi pi-external-link"
            size="small"
            severity="secondary"
            style="height: 1.5rem; width: 1.5rem"
            @click="showSource(slotProps.data.source)"
          />
        </template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="sourceDialogVisible" :style="{ width: '50vw' }">
      <highlightjs lang="yml" :code="currentSource" />
    </Dialog>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
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
  'global': { value: null, matchMode: 'contains' },
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
