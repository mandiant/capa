<template>
  <TreeTable
    :value="treeData"
    v-model:expandedKeys="expandedKeys"
    size="small"
    :filters="filters"
    :filterMode="filterMode.value"
    sortField="ppid"
    :sortOrder="1"
    removableSort
    :indentation="1.2"
    :row-hover="true"
  >
    <template #header>
      <div
        style="
          margin-bottom: 16px;
          margin-left: 16px;
          display: flex;
          justify-content: space-between;
        "
      >
        <Button icon="pi pi-expand" @click="toggleAll" label="Toggle All" />
        <IconField>
          <InputIcon class="pi pi-search" />
          <InputText v-model="filters['global']" placeholder="Global search" />
        </IconField>
      </div>
    </template>

    <Column field="processname" sortable header="Process Name" expander filterMatchMode="contains">
      <template #filter>
        <InputText
          v-model="filters['processname']"
          type="text"
          class="w-full"
          placeholder="Filter by process"
        />
      </template>
      <template #body="slotProps">
        <span v-if="slotProps.node.data.type === 'process'">
          {{ `${slotProps.node.data.processname}` }}
          <span v-if="slotProps.node.data.matchCount > 1" class="font-italic">
            ({{ slotProps.node.data.matchCount }} unique matches)
          </span>
        </span>

        <span v-else>
          {{ slotProps.node.data.processname }}

          <span class="font-italic" v-if="slotProps.node.data.matchCount > 1"
            >({{
              slotProps.node.data.matchCount + ' ' + slotProps.node.data.location
            }}
            matches)</span
          >
          <span class="font-italic" v-else>(1 {{ slotProps.node.data.location }} match)</span>
        </span>
        <Tag
          v-if="slotProps.node.data.type === 'rule' && slotProps.node.data.lib"
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
    <!-- TODO(s-ff): pid and ppid columns are identical, consider creating a resuable componenet -->
    <Column field="pid" sortable header="PID" style="width: 8%">
      <template #filter>
        <InputText
          v-model="filters['pid']"
          type="text"
          class="w-full"
          placeholder="Filter by PID"
        />
      </template>
      <template #body="slotProps">
        <span :style="{ color: getColorForId(slotProps.node.data.pid), fontWeight: 'bold' }">
          {{ slotProps.node.data.pid }}
        </span>
      </template>
    </Column>

    <Column field="ppid" sortable header="PPID" style="width: 8%">
      <template #filter>
        <InputText
          v-model="filters['ppid']"
          type="text"
          class="w-full"
          placeholder="Filter by PPID"
        />
      </template>
      <template #body="slotProps">
        <span :style="{ color: getColorForId(slotProps.node.data.ppid), fontWeight: 'bold' }">
          {{ slotProps.node.data.ppid }}
        </span>
      </template>
    </Column>

    <Column field="namespace"  header="Namespace" filterMatchMode="contains">
      <template #filter>
        <InputText
          v-model="filters['namespace']"
          type="text"
          class="w-full"
          placeholder="Filter by namespace"
        />
      </template>
    </Column>

    <Column field="source" header="Source">
      <template #body="slotProps">
        <Button
          v-if="slotProps.node.data.source"
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
</template>

<script setup>
import { ref, computed } from 'vue'
import TreeTable from 'primevue/treetable'
import Column from 'primevue/column'
import Dialog from 'primevue/dialog'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import IconField from 'primevue/iconfield'
import InputIcon from 'primevue/inputicon'
import Tag from 'primevue/tag'

const props = defineProps({
  data: {
    type: Object,
    required: true
  },
  showCapabilitiesByProcess: {
    type: Boolean,
    default: false
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

const mapMatchesToProcess = (processes, rules) => {
  const processMap = new Map()

  processes.forEach((process) => {
    const [ppid, pid] = process.address.value
    processMap.set(`${ppid},${pid}`, {
      process,
      ruleMatches: new Map()
    })
  })

  for (const ruleId in rules) {
    const rule = rules[ruleId]
    if (!props.showLibraryRules && rule.meta.lib) {
      continue
    }

    rule.matches.forEach((match) => {
      // Deconstruct the match location to get the location (first item)
      const [location] = match
      let processKey

      if (location.type === 'process') {
        const [ppid, pid] = location.value
        processKey = `${ppid},${pid}`
      } else if (location.type === 'thread' || location.type === 'call') {
        const [ppid, pid] = location.value
        processKey = `${ppid},${pid}`
      }

      if (processKey && processMap.has(processKey)) {
        const processData = processMap.get(processKey)
        const ruleKey = `${rule.meta.name}`

        if (!processData.ruleMatches.has(ruleKey)) {
          processData.ruleMatches.set(ruleKey, {
            rule,
            count: 0,
            locations: new Set()
          })
        }

        const ruleData = processData.ruleMatches.get(ruleKey)
        ruleData.count++
        ruleData.locations.add(location.type)
      }
    })
  }

  return processMap
}

const treeData = computed(() => {
  const data = []
  const processes = props.data.meta.analysis.layout.processes
  const processMap = mapMatchesToProcess(processes, props.data.rules)

  let processKey = 1

  for (const [_, { process, ruleMatches }] of processMap) {
    if (ruleMatches.size > 0) {
      const matchingRules = Array.from(ruleMatches.values()).map((ruleData, index) => ({
        key: `${process.name}-${index}`,
        data: {
          processname: `${ruleData.rule.meta.name}`,
          type: 'rule',
          lib: ruleData.rule.meta.lib,
          matchCount: ruleData.count,
          namespace: ruleData.rule.meta.namespace,
          source: ruleData.rule.source,
          location: Array.from(ruleData.locations).join(', ')
        }
      }))

      data.push({
        key: `process-${processKey++}`,
        data: {
          processname: process.name,
          type: 'process',
          lib: null,
          matchCount: ruleMatches.size,
          namespace: null,
          pid: process.address.value[1],
          ppid: process.address.value[0],
          source: null
        },
        children: matchingRules
      })
    }
  }

  return data
})

// Generate a color based on an integer value
const getColorForId = (id) => {
  // simple hash function to generate a hue value between 0 and 360
  const hue = Math.abs((id * 41) % 360)
  // use a fixed saturation and lightness for consistency
  return `hsl(${hue}, 70%, 40%)`
}
</script>
