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
      v-model:selectionKeys="selectedNodeKeys"
      @node-expand="onNodeExpand"
    >
      <template #header>
        <div
          style="
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
          "
        >
          <Button icon="pi pi-expand" @click="toggleAll" label="Toggle All" />
          <div style="display: flex; align-items: center; flex-direction: row; gap: 10px">
            <label>Toggle columns:</label>
            <MultiSelect
              :modelValue="visibleColumns"
              @update:modelValue="onToggle"
              :options="togglableColumns"
              optionLabel="header"
              class="w-full sm:w-64"
              display="chip"
              placeholder="Toggle columns"
            />
          </div>
          <IconField>
            <InputIcon class="pi pi-search" />
            <InputText v-model="filters['global']" placeholder="Global search" />
          </IconField>
        </div>
      </template>

      <!-- Name column (always visible) -->
      <Column
        field="name"
        header="Rule"
        :sortable="true"
        :expander="true"
        filterMatchMode="contains"
      >
        <template #filter>
          <InputText
            v-model="filters['name']"
            type="text"
            placeholder="Filter by Rule or Feature"
          />
        </template>
        <template #body="{ node }">
          <RuleColumn :node="node" />
        </template>
      </Column>

      <Column
        v-for="col in visibleColumns"
        :key="col.field"
        :field="col.field"
        :header="
          props.data.meta.flavor === 'dynamic' && col.field === 'address' ? 'Process' : col.header
        "
        :sortable="col.field !== 'source'"
        filterMatchMode="contains"
      >
        <!-- Filter template -->
        <template #filter v-if="col.field !== 'source'">
          <InputText
            v-model="filters[col.field]"
            type="text"
            :placeholder="`Filter by ${col.header}`"
          />
        </template>

        <!-- Address column body template -->
        <template v-if="col.field === 'address'" #body="slotProps">
          {{ slotProps.node.data.address }}
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
                  ↳ {{ technique.technique }} <span class="text-500 text-xs font-normal ml-1">({{ technique.id }})</span>
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
                {{ mbc.parts.join('::') }} <span class="text-500 text-sm font-normal opacity-80 ml-1">[{{ mbc.id }}]</span>
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

        <!-- Source column body template -->
        <template v-if="col.field === 'source'" #body="slotProps">
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
import Button from 'primevue/button'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import MultiSelect from 'primevue/multiselect'

import RuleColumn from './columns/RuleColumn.vue';

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
const selectedNodeKeys = ref([])

// Function to handle node expansion
// If one match is is expanded,
// it will collapse all the others
const onNodeExpand = (event) => {
  const expandedNodeKey = event.key
  const keyParts = expandedNodeKey.split('-')

  // Check if the expanded node is a match node (key format: n-m)
  if (keyParts.length === 2) {
    const parentKey = keyParts[0]

    // Collapse all sibling match nodes
    Object.keys(expandedKeys.value).forEach((key) => {
      if (
        key.startsWith(parentKey + '-') &&
        key.split('-').length == 2 &&
        key !== expandedNodeKey
      ) {
        expandedKeys.value[key] = false
      }
    })
  }
}

// Function to expand all children of a node
const expandAllChildren = (node) => {
  if (node.children) {
    node.children.forEach((child) => {
      expandedKeys.value[child.key] = true
      expandAllChildren(child)
    })
  }
}

// All available columns
const togglableColumns = ref([
  { field: 'address', header: 'Address' },
  { field: 'tactic', header: 'ATT&CK Tactic' },
  { field: 'namespace', header: 'Namespace' },
  { field: 'mbc', header: 'Malware Behaviour Catalogue' },
  { field: 'source', header: 'Source' }
])

// Define initially visible columns (excluding 'mbc' and 'address')
const visibleColumns = ref(
  togglableColumns.value.filter((col) => col.field !== 'mbc' && col.field !== 'address')
)

const onToggle = (val) => {
  visibleColumns.value = togglableColumns.value.filter((col) => val.includes(col))
}

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

// Expand/Collapse All nodes
const toggleAll = () => {
  const anyRootExpanded = treeData.value.some((rootNode) => expandedKeys.value[rootNode.key])

  if (!anyRootExpanded) {
    // Expand all root nodes and their first match node
    treeData.value.forEach((rootNode) => {
      expandedKeys.value[rootNode.key] = true
      if (rootNode.children && rootNode.children.length > 0) {
        // Expand only the first match node
        expandedKeys.value[rootNode.children[0].key] = true
        // Expand all children of the first match node
        expandAllChildren(rootNode.children[0])
      }
    })
  } else {
    // Collapse only root
    treeData.value.forEach((rootNode) => {
      expandedKeys.value[rootNode.key] = false
    })
  }
}

onMounted(() => {
  if (props.data && props.data.rules) {
    treeData.value = parseRules(props.data.rules, props.data.meta.flavor)
    expandedKeys.value = {}
    treeData.value.forEach((rootNode) => {
      expandedKeys.value[rootNode.key] = false
      if (rootNode.children) {
        rootNode.children.forEach((matchNode) => {
          expandedKeys.value[matchNode.key] = false
          if (matchNode.children) {
            expandAllChildren(matchNode)
          }
        })
        expandedKeys.value[rootNode.children[0].key] = true
      }
    })
  } else {
    console.error('Invalid data prop:', props.data)
  }
})

/**
 * Formats an MBC (Malware Behavior Catalog) object into a string representation.
 *
 * @param {Object} mbc - The MBC object to format.
 * @returns {string} A string representation of the MBC object.
 *
 * e.g. "Anti-Behavioral Analysis::Virtual Machine Detection::Human User Check [B0009.012]"
 */

const formatMBC = (mbc) => {
  return `${mbc.parts.join('::')} [${mbc.id}]`
}

function createMBCHref(mbc) {
  let baseUrl;

  // Determine the base URL based on the id
  if (mbc.id.startsWith('B')) {
    baseUrl = 'https://github.com/MBCProject/mbc-markdown/blob/main';
  } else if (mbc.id.startsWith('C')) {
    baseUrl = 'https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors';
  } else {
    return null
  }

  // Convert the objective and behavior to lowercase and replace spaces with hyphens
  const objectivePath = mbc.objective.toLowerCase().replace(/\s+/g, '-');
  const behaviorPath = mbc.behavior.toLowerCase().replace(/\s+/g, '-');

  // Construct the final URL
  return `${baseUrl}/${objectivePath}/${behaviorPath}.md`;
}

/**
 * Creates a MITRE ATT&CK URL for a specific technique or sub-technique.
 *
 * @param {Object} attack - The ATT&CK object containing information about the technique.
 * @param {string} attack.id - The ID of the ATT&CK technique or sub-technique.
 * @returns {string} The formatted MITRE ATT&CK URL for the technique.
 */
 function createATTACKHref(attack) {
  const baseUrl = 'https://attack.mitre.org/techniques/';
  const idParts = attack.id.split('.');

  if (idParts.length === 1) {
    // It's a main technique
    return `${baseUrl}${idParts[0]}`;
  } else if (idParts.length === 2) {
    // It's a sub-technique
    return `${baseUrl}${idParts[0]}/${idParts[1]}`;
  } else {
    return null
  }
}

</script>

<style scoped>
/* Optional: Add a subtle background to root-level rows for better distinction  */
:deep(.p-treetable-tbody > tr[aria-level='1']) {
  background-color: #f9f9f9;
}

/* tighten up the spacing between rows */
:deep(.p-treetable-tbody > tr > td) {
  padding: 0rem 0.5rem !important;
}
</style>
