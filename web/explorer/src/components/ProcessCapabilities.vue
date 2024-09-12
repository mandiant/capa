<template>
    <div class="card">
        <TreeTable
            :value="processTree"
            v-model:expandedKeys="expandedKeys"
            :filters="filters"
            filterMode="lenient"
            sortField="pid"
            :sortOrder="1"
            :rowHover="true"
        >
            <Column field="processname" header="Process" expander>
                <template #body="slotProps">
                    <span
                        :id="'process-' + slotProps.node.key"
                        class="cursor-pointer flex align-items-center"
                        @mouseenter="showTooltip($event, slotProps.node)"
                        @mouseleave="hideTooltip"
                    >
                        <span
                            class="text-lg text-overflow-ellipsis overflow-hidden white-space-nowrap inline-block max-w-20rem font-monospace"
                        >
                            {{ slotProps.node.data.processname }}
                        </span>
                        <span class="ml-2">- PID: {{ slotProps.node.data.pid }}</span>
                        <span v-if="slotProps.node.data.uniqueMatchCount > 0" class="font-italic ml-2 match-count">
                            ({{ slotProps.node.data.uniqueMatchCount }} unique
                            {{ slotProps.node.data.uniqueMatchCount > 1 ? "matches" : "match" }})
                        </span>
                    </span>
                </template>
            </Column>
            <Column field="pid" header="PID" sortable>
                <template #body="slotProps">
                    <span :style="{ color: getColorForId(slotProps.node.data.pid) }">
                        {{ slotProps.node.data.pid }}
                    </span>
                </template>
            </Column>
            <Column field="ppid" header="PPID" sortable>
                <template #body="slotProps">
                    <span :style="{ color: getColorForId(slotProps.node.data.ppid) }">
                        {{ slotProps.node.data.ppid }}
                    </span>
                </template>
            </Column>
        </TreeTable>

        <div
            v-if="tooltipVisible"
            class="fixed bg-gray-800 text-white p-3 border-round-sm z-5 max-w-50rem shadow-2"
            :style="tooltipStyle"
        >
            <div v-for="rule in currentNode.data.uniqueRules" :key="rule.name">
                • {{ rule.name }}
                <span class="font-italic match-count">
                    ({{ rule.matchCount }} {{ rule.scope }} {{ rule.matchCount > 1 ? "matches" : "match" }})
                </span>
                <LibraryTag v-if="rule.lib" />
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from "vue";
import TreeTable from "primevue/treetable";
import Column from "primevue/column";
import LibraryTag from "@/components/misc/LibraryTag.vue";

const props = defineProps({
    data: {
        type: Object,
        required: true
    },
    showLibraryRules: {
        type: Boolean,
        default: false
    }
});

const filters = ref({});
const expandedKeys = ref({});
const tooltipVisible = ref(false);
const currentNode = ref(null);
const tooltipStyle = ref({
    position: "fixed",
    top: "0px",
    left: "0px"
});

const getProcessIds = (location) => {
    if (!location || location.type === "no address") {
        return null;
    }
    if (Array.isArray(location.value) && location.value.length >= 2) {
        return {
            ppid: location.value[0],
            pid: location.value[1]
        };
    }
    return null;
};

const processTree = computed(() => {
    if (
        !props.data ||
        !props.data.meta ||
        !props.data.meta.analysis ||
        !props.data.meta.analysis.layout ||
        !props.data.meta.analysis.layout.processes
    ) {
        console.error("Invalid data structure");
        return [];
    }

    const processes = props.data.meta.analysis.layout.processes;
    const rules = props.data.rules || {};
    const processMap = new Map();

    // create all process nodes
    processes.forEach((process) => {
        if (!process.address || !Array.isArray(process.address.value) || process.address.value.length < 2) {
            console.warn("Invalid process structure", process);
            return;
        }
        const [ppid, pid] = process.address.value;
        processMap.set(pid, {
            key: `process-${pid}`,
            data: {
                processname: process.name || "<Unknown Process>",
                pid,
                ppid,
                uniqueMatchCount: 0,
                uniqueRules: new Map()
            },
            children: []
        });
    });

    // build the tree structure and add rule matches
    Object.entries(rules).forEach(([ruleName, rule]) => {
        if (!props.showLibraryRules && rule.meta && rule.meta.lib) return;
        if (!rule.matches || !Array.isArray(rule.matches)) return;

        rule.matches.forEach((match) => {
            if (!Array.isArray(match) || match.length === 0) return;
            const [location] = match;
            const ids = getProcessIds(location);
            if (ids && processMap.has(ids.pid)) {
                const processNode = processMap.get(ids.pid);
                if (!processNode.data.uniqueRules.has(ruleName)) {
                    processNode.data.uniqueMatchCount++;
                    processNode.data.uniqueRules.set(ruleName, {
                        name: ruleName,
                        lib: rule.meta && rule.meta.lib,
                        matchCount: 0,
                        scope: location.type
                    });
                }
                processNode.data.uniqueRules.get(ruleName).matchCount++;
            }
        });
    });
    // build the final tree structure
    const rootProcesses = [];
    processMap.forEach((processNode) => {
        processNode.data.uniqueRules = Array.from(processNode.data.uniqueRules.values());
        const parentProcess = processMap.get(processNode.data.ppid);
        if (parentProcess) {
            parentProcess.children.push(processNode);
        } else {
            rootProcesses.push(processNode);
        }
    });

    return rootProcesses;
});

const getColorForId = (id) => {
    if (id === undefined || id === null) return "black";
    const hue = Math.abs((id * 41) % 360);
    return `hsl(${hue}, 70%, 40%)`;
};

const showTooltip = (event, node) => {
    if (node.data.uniqueMatchCount > 0) {
        currentNode.value = node;
        tooltipVisible.value = true;
        updateTooltipPosition(event);
    }
};

const hideTooltip = () => {
    tooltipVisible.value = false;
    currentNode.value = null;
};

const updateTooltipPosition = (event) => {
    const offset = 10;
    tooltipStyle.value = {
        position: "fixed",
        top: `${event.clientY + offset}px`,
        left: `${event.clientX + offset}px`
    };
};

const handleMouseMove = (event) => {
    if (tooltipVisible.value) {
        updateTooltipPosition(event);
    }
};

onMounted(() => {
    document.addEventListener("mousemove", handleMouseMove);
});

onUnmounted(() => {
    document.removeEventListener("mousemove", handleMouseMove);
});
</script>
