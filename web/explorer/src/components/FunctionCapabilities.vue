<template>
    <DataTable
        :value="tableData"
        rowGroupMode="rowspan"
        groupRowsBy="address"
        removableSort
        size="small"
        :filters="filters"
        :filterMode="filterMode"
        :globalFilterFields="['funcaddr', 'ruleName', 'namespace']"
    >
        <template #header>
            <IconField>
                <InputIcon class="pi pi-search" />
                <InputText v-model="filters['global'].value" placeholder="Global search" />
            </IconField>
        </template>

        <Column field="address" sortable header="Function Address" :rowspan="3" class="w-min">
            <template #body="{ data }">
                <span class="font-monospace">{{ data.address }}</span>
                <span v-if="data.matchCount > 1" class="font-italic">
                    ({{ data.matchCount }} match{{ data.matchCount > 1 ? "es" : "" }})
                </span>
            </template>
        </Column>

        <Column field="rule" sortable header="Matches" class="w-min">
            <template #body="{ data }">
                {{ data.rule }}
                <LibraryTag v-if="data.lib" />
            </template>
        </Column>

        <Column field="namespace" sortable header="Namespace"></Column>
    </DataTable>

    <Dialog v-model:visible="sourceDialogVisible" :style="{ width: '50vw' }">
        <highlightjs lang="yml" :code="currentSource" class="bg-white" />
    </Dialog>
</template>

<script setup>
import { ref, computed, onMounted } from "vue";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
import Dialog from "primevue/dialog";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";
import LibraryTag from "@/components/misc/LibraryTag.vue";

import { parseFunctionCapabilities } from "@/utils/rdocParser";

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

const filters = ref({ global: { value: null, matchMode: "contains" } });
const filterMode = ref("lenient");
const sourceDialogVisible = ref(false);
const currentSource = ref("");

const functionCapabilities = ref([]);

onMounted(() => {
    functionCapabilities.value = parseFunctionCapabilities(props.data);
});

/*
 * tableData is the data passed to the DataTable component
 * it is a computed property (that is because it gets re-executed everytime props.showLibraryRules changes)
 * it is an array of objects, where each object represents a row in the table
 * it also converts the output of parseFunctionCapabilities into a format that can be used by the DataTable component
 */

const tableData = computed(() => {
    const data = [];
    for (const fcaps of functionCapabilities.value) {
        const capabilities = fcaps.capabilities;
        for (const capability of capabilities) {
            if (capability.lib && !props.showLibraryRules) continue;
            data.push({
                address: fcaps.address,
                matchCount: capabilities.length,
                rule: capability.name,
                namespace: capability.namespace,
                lib: capability.lib
            });
        }
    }
    return data;
});
</script>

<style scoped>
/* tighten up the spacing between rows */
:deep(.p-datatable.p-datatable-sm .p-datatable-tbody > tr > td) {
    padding: 0.2rem 0.5rem !important;
}
</style>
