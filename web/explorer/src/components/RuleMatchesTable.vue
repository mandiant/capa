<template>
    <TreeTable
        :value="filteredTreeData"
        v-model:expandedKeys="expandedKeys"
        size="small"
        :scrollable="true"
        :filters="filters"
        :filterMode="filterMode"
        sortField="namespace"
        :sortOrder="1"
        removableSort
        :rowHover="true"
        :indentation="1.3"
        selectionMode="single"
        @node-select="onNodeSelect"
        :pt="{
            row: ({ instance }) => ({
                oncontextmenu: (event) => onRightClick(event, instance)
            })
        }"
    >
        <template #header>
            <IconField>
                <InputIcon class="pi pi-search" />
                <InputText v-model="filters['global']" placeholder="Global search" />
            </IconField>
        </template>

        <!-- Rule column  -->
        <Column
            field="name"
            header="Rule"
            :sortable="true"
            :expander="true"
            filterMatchMode="contains"
            style="width: 38%"
            class="cursor-default"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText
                    v-model="filters['name']"
                    type="text"
                    placeholder="Filter by rule or nested feature"
                    class="w-full"
                />
            </template>
            <template #body="{ node }">
                <RuleColumn :node="node" />
            </template>
        </Column>

        <!-- Address column (only shown for static flavor)  -->
        <Column
            v-if="props.data.meta.flavor === 'static'"
            field="address"
            header="Address"
            filterMatchMode="contains"
            style="width: 8.5%"
            class="cursor-default"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText
                    v-model="filters['address']"
                    type="text"
                    :placeholder="`Filter by ${props.data.meta.flavor === 'dynamic' ? 'process' : 'address'}`"
                    class="w-full"
                />
            </template>
            <template #body="{ node }">
                <span class="font-monospace text-sm">{{ node.data.address }}</span>
            </template>
        </Column>

        <!-- Namespace column -->
        <Column
            field="namespace"
            header="Namespace"
            sortable
            filterMatchMode="contains"
            style="width: 16%"
            class="cursor-default"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText v-model="filters['namespace']" type="text" placeholder="Filter by namespace" />
            </template>
        </Column>

        <!-- Technique column -->
        <Column
            field="attack"
            header="ATT&CK Technique"
            sortable
            :sortField="(node) => node?.attack[0]?.technique"
            filterField="attack.0.parts"
            filterMatchMode="contains"
            style="width: 15%"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText
                    v-model="filters['attack.0.parts']"
                    type="text"
                    placeholder="Filter by technique"
                    class="w-full"
                />
            </template>
            <template #body="{ node }">
                <div class="flex flex-wrap">
                    <div v-for="(attack, index) in node.data.attack" :key="index">
                        <a :href="createATTACKHref(attack)" target="_blank">
                            {{ attack.technique }}
                            <span class="text-500 text-sm font-normal ml-1">({{ attack.id.split(".")[0] }})</span>
                        </a>
                        <div v-if="attack.subtechnique" style="font-size: 0.8em; margin-left: 2em">
                            <a :href="createATTACKHref(attack)" target="_blank">
                                ↳ {{ attack.subtechnique }}
                                <span class="text-500 text-xs font-normal ml-1">({{ attack.id }})</span>
                            </a>
                        </div>
                    </div>
                </div>
            </template>
        </Column>

        <!-- MBC column -->
        <Column
            field="mbc"
            header="Malware Behavior Catalog"
            sortable
            :sortField="(node) => node?.mbc[0]?.parts[0]"
            filterField="mbc.0.parts"
            filterMatchMode="contains"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText v-model="filters['mbc.0.parts']" type="text" placeholder="Filter by MBC" class="w-full" />
            </template>
            <template #body="{ node }">
                <div class="flex flex-wrap">
                    <div v-for="(mbc, index) in node.data.mbc" :key="index">
                        <a :href="createMBCHref(mbc)" target="_blank">
                            {{ mbc.parts.join("::") }}
                            <span class="text-500 text-sm font-normal opacity-80 ml-1">[{{ mbc.id }}]</span>
                        </a>
                    </div>
                </div>
            </template>
        </Column>
    </TreeTable>

    <!-- Right click context menu -->
    <ContextMenu ref="menu" :model="contextMenuItems">
        <template #item="{ item, props }">
            <a v-ripple v-bind="props.action" :href="item.url" :target="item.target">
                <span v-if="item.icon !== 'vt-icon'" :class="item.icon" />
                <VTIcon v-else-if="item.icon === 'vt-icon'" />
                <span>{{ item.label }}</span>
                <i v-if="item.description" class="pi pi-info-circle text-xs" v-tooltip.right="item.description" />
            </a>
        </template>
    </ContextMenu>

    <!-- Source code dialog -->
    <Dialog v-model:visible="sourceDialogVisible" style="width: 50vw">
        <highlightjs autodetect :code="currentSource" />
    </Dialog>
</template>

<script setup>
// Used to highlight function calls in dynamic mode
import "highlight.js/styles/stackoverflow-light.css";

import { ref, onMounted, computed } from "vue";
import TreeTable from "primevue/treetable";
import InputText from "primevue/inputtext";
import Dialog from "primevue/dialog";
import Column from "primevue/column";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import ContextMenu from "primevue/contextmenu";

import RuleColumn from "@/components/columns/RuleColumn.vue";
import VTIcon from "@/components/misc/VTIcon.vue";

import { parseRules } from "@/utils/rdocParser";
import { createMBCHref, createATTACKHref, createCapaRulesUrl, createVirusTotalUrl } from "@/utils/urlHelpers";

const props = defineProps({
    data: {
        type: Object,
        required: true
    },
    showLibraryRules: {
        type: Boolean,
        default: false
    },
    showColumnFilters: {
        type: Boolean,
        default: false
    }
});

const treeData = ref([]);

// The `filters` ref in the setup section is used by PrimeVue to maintain the overall filter
// state of the table. Each column's filter contributes to this overall state.
const filters = ref({});

const filterMode = ref("lenient");
const sourceDialogVisible = ref(false);
const currentSource = ref("");

// expandedKeys keeps track of the nodes that are expanded
// for example, if a node with key "0" is expanded (and its first child is also expanded), expandedKeys will be { "0": true, "0-0": true }
// if the entire tree is collapsed expandedKeys will be {}
const expandedKeys = ref({});

// selectedNode is used as placeholder for the node that is right-clicked
const menu = ref();
const selectedNode = ref({});
const contextMenuItems = computed(() => [
    {
        label: "Copy rule name",
        icon: "pi pi-copy",
        command: () => {
            navigator.clipboard.writeText(selectedNode.value.data?.name);
        }
    },
    {
        label: "View source",
        icon: "pi pi-eye",
        command: () => {
            showSource(selectedNode.value.data?.source);
        }
    },
    {
        label: "View rule in capa-rules",
        icon: "pi pi-external-link",
        target: "_blank",
        url: createCapaRulesUrl(selectedNode.value)
    },
    {
        label: "Lookup rule in VirusTotal",
        icon: "vt-icon",
        target: "_blank",
        description: "Requires VirusTotal Premium account",
        url: createVirusTotalUrl(selectedNode.value.data?.name)
    }
]);

const onRightClick = (event, instance) => {
    if (instance.node.data.source) {
        // We only enable right-click context menu on rows that have
        // a source field (i.e. rules and `- match` features)
        selectedNode.value = instance.node;

        // show the context menu
        menu.value.show(event);
    }
};

/**
 * Handles the expansion and collapse of nodes
 *
 * @param {Object} node - The selected node
 *
 * @example
 * // Expanding a rule node
 * onNodeSelect({
 *   key: '3',
 *   data: { type: 'rule', name: 'test rule', namespace: 'namespace', ... }
 *   children: [
 *      {
 *          key: '3-0',
 *          data: { type: 'match location', name: 'function @ 0x1000', namespace: null, ... }
 *          children: []
 *      }
 *   ]
 * });
 * // Result: expandedKeys.value = { '3': true, '3-0': true }
 */
const onNodeSelect = (node) => {
    const nodeKey = node.key;
    const nodeType = node.data.type;

    // We only expand rule and match locations, otherwise return
    if (nodeType !== "rule" && nodeType !== "match location") return;

    // If the node is already expanded, collapse it
    if (expandedKeys.value[nodeKey]) {
        delete expandedKeys.value[nodeKey];
        return;
    }

    if (nodeType === "rule") {
        // For rule nodes, clear existing expanded keys and set the clicked rule as expanded
        // and expand the first (child) match by default
        expandedKeys.value = { [nodeKey]: true, [`${nodeKey}-0`]: true };
    } else if (nodeType === "match location") {
        // For match location nodes, we need to keep the parent expanded
        // and toggle the clicked node while collapsing siblings
        const [parentKey] = nodeKey.split("-");
        expandedKeys.value = { [parentKey]: true, [`${nodeKey}`]: true };
    }
};

// Filter out the treeData for showing/hiding lib rules
const filteredTreeData = computed(() => {
    if (props.showLibraryRules) {
        return treeData.value; // Return all data when showLibraryRules is true
    } else {
        // Filter out library rules when showLibraryRules is false
        const filterNode = (node) => {
            if (node.data && node.data.lib) {
                return false;
            }
            if (node.children) {
                node.children = node.children.filter(filterNode);
            }
            return true;
        };
        return treeData.value.filter(filterNode);
    }
});

/**
 * Sets the source code of a node in the dialog.
 *
 * @param {string} source - The source code to be displayed.
 */
const showSource = (source) => {
    currentSource.value = source;
    sourceDialogVisible.value = true;
};

onMounted(() => {
    treeData.value = parseRules(props.data.rules, props.data.meta.flavor, props.data.meta.analysis.layout);
});
</script>

<style scoped>
/* Disable the toggle button for statement and features */
:deep(
        .p-treetable-tbody
            > tr:not(:is([aria-level="1"], [aria-level="2"]))
            > td
            > div
            > .p-treetable-node-toggle-button
    ) {
    visibility: hidden !important;
    height: 1.3rem;
}

/* Make all matches nodes (i.e. not rule names) slightly smaller,
and tighten up the spacing between the rows  */
:deep(.p-treetable-tbody > tr:not([aria-level="1"]) > td) {
    font-size: 0.95rem;
    padding: 0rem 0.5rem !important;
}

/* Optional: Add a subtle background to root-level rows for better distinction  */
:deep(.p-treetable-tbody > tr[aria-level="1"]) {
    background-color: #f9f9f9;
}
</style>
