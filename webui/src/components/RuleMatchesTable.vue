<template>
  <div class="card">
    <TreeTable
      :value="filteredTreeData"
      v-model:expandedKeys="expandedKeys"
      size="small"
      :filters="filters"
      :filterMode="filterMode.value"
      sortField="namespace"
      :sortOrder="-1"
      removableSort
      :rowHover="true"
      :indentation="1.3"
      selectionMode="single"
      @nodeExpand="onNodeSelect"
      @nodeSelect="onNodeSelect"
      :pt="{
        row: ({ instance }) => ({
          oncontextmenu: (event) => onRightClick(event, instance)
        })
      }"
    >
      <template #header>
        <div style="display: flex; justify-content: end; align-items: center">
          <IconField>
            <InputIcon class="pi pi-search" />
            <InputText v-model="filters['global']" placeholder="Global search" />
          </IconField>
        </div>
      </template>

      <!-- Name column (always visible) -->
      <Column field="name" header="Rule" :sortable="true" :expander="true" filterMatchMode="contains">
        <template #filter>
          <InputText v-model="filters['name']" type="text" placeholder="Filter by Rule or Feature" />
        </template>
        <template #body="{ node }">
          <RuleColumn :node="node" />
        </template>
      </Column>

      <Column
        v-for="col in visibleColumns"
        :key="col.field"
        :field="col.field"
        :header="props.data.meta.flavor === 'dynamic' && col.field === 'address' ? 'Process' : col.header"
        :sortable="col.field !== 'source'"
        :class="{ 'w-3': col.field === 'mbc', 'w-full': col.field === 'name' }"
        filterMatchMode="contains"
      >
        <!-- Filter template -->
        <template #filter>
          <InputText v-model="filters[col.field]" type="text" :placeholder="`Filter by ${col.header}`" />
        </template>

        <!-- Address column body template -->
        <template v-if="col.field === 'address'" #body="slotProps">
          <span style="font-family: monospace">
            {{ slotProps.node.data.type === 'match location' ? '' : slotProps.node.data.address }}
          </span>
        </template>

        <!-- Tactic column body template -->
        <template v-if="col.field === 'tactic'" #body="slotProps">
          <div v-if="slotProps.node.data.attack">
            <div v-for="(attack, index) in slotProps.node.data.attack" :key="index">
              <a :href="createATTACKHref(attack)" target="_blank">
                {{ attack.technique }} <span class="text-500 text-sm font-normal ml-1">({{ attack.id }})</span>
              </a>
              <div
                v-for="(technique, techIndex) in attack.techniques"
                :key="techIndex"
                style="font-size: 0.8em; margin-left: 1em"
              >
                <a :href="createATTACKHref(technique)" target="_blank">
                  ↳ {{ technique.technique }}
                  <span class="text-500 text-xs font-normal ml-1">({{ technique.id }})</span>
                </a>
              </div>
            </div>
          </div>
        </template>

        <!-- MBC column body template -->
        <template v-if="col.field === 'mbc'" #body="slotProps">
          <div v-if="slotProps.node.data.mbc">
            <div v-for="(mbc, index) in slotProps.node.data.mbc" :key="index">
              <a :href="createMBCHref(mbc)" target="_blank">
                {{ mbc.parts.join('::') }}
                <span class="text-500 text-sm font-normal opacity-80 ml-1">[{{ mbc.id }}]</span>
              </a>
            </div>
          </div>
        </template>

        <!-- Namespace column body template -->
        <template v-if="col.field === 'namespace'" #body="slotProps">
          <span v-if="!slotProps.node.data.lib">
            {{ slotProps.node.data.namespace }}
          </span>
        </template>
      </Column>
    </TreeTable>
    <ContextMenu ref="menu" :model="contextMenuItems">
      <template #item="{ item, props }">
        <a v-ripple v-bind="props.action" :href="item.url" :target="item.target">
          <span v-if="item.icon !== 'vt-icon'" :class="item.icon" />
          <VTIcon v-else-if="item.icon === 'vt-icon'" />
          <span>{{ item.label }}</span>
        </a>
      </template>
    </ContextMenu>

    <Toast />

    <Dialog v-model:visible="sourceDialogVisible" :style="{ width: '50vw' }">
      <highlightjs autodetect :code="currentSource" />
    </Dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import TreeTable from 'primevue/treetable'
import InputText from 'primevue/inputtext'
import Dialog from 'primevue/dialog'
import Column from 'primevue/column'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import ContextMenu from 'primevue/contextmenu'

import RuleColumn from './columns/RuleColumn.vue'
import VTIcon from './misc/VTIcon.vue'

import { parseRules } from '../utils/rdocParser'

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

const treeData = ref([])
const filters = ref({})
const filterMode = ref({ value: 'lenient' })
const sourceDialogVisible = ref(false)
const currentSource = ref('')
const expandedKeys = ref({})

const menu = ref()
const selectedNode = ref({})

const contextMenuItems = computed(() => [
  {
    label: 'View source',
    icon: 'pi pi-eye',
    command: () => {
      showSource(selectedNode.value.data.source)
    }
  },
  {
    label: 'View rule in capa-rules',
    icon: 'pi pi-external-link',
    target: '_blank',
    url: selectedNode.value.url
  },
  {
    label: 'Lookup rule in VirusTotal',
    icon: 'vt-icon',
    target: '_blank',
    url: selectedNode.value.vturl
  }
])

const onRightClick = (event, instance) => {
  if (instance.node.data.source) {
    selectedNode.value = instance.node
    // contrust capa-rules url
    selectedNode.value.url = `https://github.com/mandiant/capa-rules/blob/master/${instance.node.data.namespace || 'lib'}/${instance.node.data.name.toLowerCase().replace(/\s+/g, '-')}.yml`
    // construct VirusTotal deep link
    const behaviourSignature = `behaviour_signature:"${instance.node.data.name}"`
    selectedNode.value.vturl = `https://www.virustotal.com/gui/search/${behaviourSignature}/files`

    menu.value.show(event)
  }
}

/*
 * Expand node on click
 */
const onNodeSelect = (node) => {
  const nodeKey = node.key
  const nodeType = node.data.type

  if (nodeType === 'rule') {
    // For rule nodes, clear existing expanded keys and set the clicked rule as expanded
    // expand the first (child) match by default
    expandedKeys.value = { [nodeKey]: true, [`${nodeKey}-0`]: true }
  } else if (nodeType === 'match location') {
    // For match location nodes, we need to keep the parent expanded
    // and toggle the clicked node while collapsing siblings
    const [parentKey, _] = nodeKey.split('-')
    expandedKeys.value = { [parentKey]: true, [`${nodeKey}`]: true }
  } else {
    return
  }
}

// All available columns
const togglableColumns = ref([
  { field: 'address', header: 'Address' },
  { field: 'namespace', header: 'Namespace' },
  { field: 'tactic', header: 'ATT&CK Tactic' },
  { field: 'mbc', header: 'Malware Behaviour Catalogue' }
])

// Define initially visible columns (excluding 'mbc' and 'address')
const visibleColumns = ref(
  togglableColumns.value
  //togglableColumns.value.filter((col) => col.field !== 'mbc' && col.field !== 'address')
  //togglableColumns.value.filter((col) => col.field !== 'address')
)

// Filter out the treeData for showing/hiding lib rules
const filteredTreeData = computed(() => {
  if (props.showLibraryRules) {
    return treeData.value // Return all data when showLibraryRules is true
  } else {
    // Filter out library rules when showLibraryRules is false
    const filterNode = (node) => {
      if (node.data && node.data.lib) {
        return false
      }
      if (node.children) {
        node.children = node.children.filter(filterNode)
      }
      return true
    }
    return treeData.value.filter(filterNode)
  }
})

const showSource = (source) => {
  currentSource.value = source
  sourceDialogVisible.value = true
}

onMounted(() => {
  if (props.data && props.data.rules) {
    treeData.value = parseRules(props.data.rules, props.data.meta.flavor, props.data.meta.analysis.layout)
  } else {
    console.error('Invalid data prop:', props.data)
  }
})

/**
 * Creates an MBC (Malware Behavior Catalog) URL from an MBC object.
 *
 * @param {Object} mbc - The MBC object to format.
 * @returns {string} The MBC URL.
 */

function createMBCHref(mbc) {
  let baseUrl

  // Determine the base URL based on the id
  if (mbc.id.startsWith('B')) {
    // Behavior
    baseUrl = 'https://github.com/MBCProject/mbc-markdown/blob/main'
  } else if (mbc.id.startsWith('C')) {
    // Micro-Behavior
    baseUrl = 'https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors'
  } else {
    return null
  }

  // Convert the objective and behavior to lowercase and replace spaces with hyphens
  const objectivePath = mbc.objective.toLowerCase().replace(/\s+/g, '-')
  const behaviorPath = mbc.behavior.toLowerCase().replace(/\s+/g, '-')

  // Construct the final URL
  return `${baseUrl}/${objectivePath}/${behaviorPath}.md`
}

/**
 * Creates a MITRE ATT&CK URL for a specific technique or sub-technique.
 *
 * @param {Object} attack - The ATT&CK object containing information about the technique.
 * @param {string} attack.id - The ID of the ATT&CK technique or sub-technique.
 * @returns {string} The formatted MITRE ATT&CK URL for the technique.
 */
function createATTACKHref(attack) {
  const baseUrl = 'https://attack.mitre.org/techniques/'
  const idParts = attack.id.split('.')

  if (idParts.length === 1) {
    // It's a technique
    return `${baseUrl}${idParts[0]}`
  } else if (idParts.length === 2) {
    // It's a sub-technique
    return `${baseUrl}${idParts[0]}/${idParts[1]}`
  } else {
    return null
  }
}
</script>

<style scoped>
/* Disable the toggle button for statement and features */
:deep(
    .p-treetable-tbody > tr:not(:is([aria-level='1'], [aria-level='2'])) > td > div > .p-treetable-node-toggle-button
  ) {
  visibility: hidden !important;
  height: 1.3rem;
}
/* Disable the toggle button for rules */
:deep(.p-treetable-tbody > tr:is([aria-level='1']) > td > div > .p-treetable-node-toggle-button) {
  visibility: collapse !important;
  height: 1.3rem;
}

/* Make all matches nodes (i.e. not rule names) slightly smaller,
and tighten up the spacing between the rows  */
:deep(.p-treetable-tbody > tr:not([aria-level='1']) > td) {
  font-size: 0.95rem;
  padding: 0rem 0.5rem !important;
}

/* Optional: Add a subtle background to root-level rows for better distinction  */
:deep(.p-treetable-tbody > tr[aria-level='1']) {
  background-color: #f9f9f9;
}
</style>
