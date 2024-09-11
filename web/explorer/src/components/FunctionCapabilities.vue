<template>
    <DataTable
        :value="tableData"
        rowGroupMode="rowspan"
        groupRowsBy="address"
        removableSort
        size="small"
        :filters="filters"
        :filterMode="filterMode"
        filterDisplay="row"
        :globalFilterFields="['address', 'rule', 'namespace']"
    >
        <template #header>
            <IconField>
                <InputIcon class="pi pi-search" />
                <InputText v-model="filters['global'].value" placeholder="Global search" />
            </IconField>
        </template>

        <Column
            field="address"
            sortable
            header="Function Address"
            class="w-min"
            :showFilterMenu="false"
            :showClearButton="false"
        >
            <template #filter v-if="props.showColumnFilters">
                <InputText v-model="filters['address'].value" placeholder="Filter by function address" />
            </template>
            <template #body="{ data }">
                <span class="font-monospace">{{ data.address }}</span>
                <span v-if="data.matchCount > 1" class="font-italic match-count">
                    ({{ data.matchCount }} match{{ data.matchCount > 1 ? "es" : "" }})
                </span>
            </template>
        </Column>

        <Column field="rule" header="Rule Matches" class="w-min" :showFilterMenu="false" :showClearButton="false">
            <template #filter v-if="props.showColumnFilters">
                <InputText v-model="filters['rule'].value" placeholder="Filter by rule" />
            </template>
            <template #body="{ data }">
                {{ data.rule }}
                <LibraryTag v-if="data.lib" />
            </template>
        </Column>

        <Column field="namespace" header="Namespace" :showFilterMenu="false" :showClearButton="false">
            <template #filter v-if="props.showColumnFilters">
                <InputText v-model="filters['namespace'].value" placeholder="Filter by namespace" />
            </template>
        </Column>
    </DataTable>
</template>

<script setup>
import { ref, computed, onMounted } from "vue";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
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
    },
    showColumnFilters: {
        type: Boolean,
        default: false
    }
});

const filters = ref({
    global: { value: null, matchMode: "contains" },
    address: { value: null, matchMode: "contains" },
    rule: { value: null, matchMode: "contains" },
    namespace: { value: null, matchMode: "contains" }
});
const filterMode = ref("lenient");

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
        // when props.showLibraryRules is true, all capabilities are included.
        // when props.showLibraryRules is false, only non-library capabilities (where cap.lib is false) are included.
        const capabilities = fcaps.capabilities.filter((cap) => props.showLibraryRules || !cap.lib);
        capabilities.forEach((capability) => {
            data.push({
                address: fcaps.address,
                matchCount: capabilities.length,
                rule: capability.name,
                namespace: capability.namespace,
                lib: capability.lib
            });
        });
    }
    return data;
});
</script>

<style scoped>
/* tighten up the spacing between rows, and change border color */
:deep(.p-datatable-tbody > tr > td) {
    padding: 0.2rem 0.5rem !important;
    border-width: 0 0 1px 0;
    border-color: #97a0ab;
}
</style>
