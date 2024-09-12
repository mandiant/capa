<template>
    <Card>
        <template #content>
            <div class="flex align-items-center flex-wrap gap-3">
                <div class="flex flex-row align-items-center gap-2">
                    <Checkbox
                        v-model="showCapabilitiesByFunctionOrProcess"
                        inputId="showCapabilitiesByFunctionOrProcess"
                        :binary="true"
                        :disabled="showNamespaceChart"
                    />
                    <label for="showCapabilitiesByFunctionOrProcess">{{ capabilitiesLabel }}</label>
                </div>
                <div class="flex flex-row align-items-center gap-2">
                    <Checkbox
                        v-model="showLibraryRules"
                        inputId="showLibraryRules"
                        :binary="true"
                        :disabled="showNamespaceChart || libraryRuleMatchesCount === 0"
                    />
                    <label for="showLibraryRules">
                        <span v-if="libraryRuleMatchesCount > 1">
                            Show {{ libraryRuleMatchesCount }} distinct library rules
                        </span>
                        <span v-else-if="libraryRuleMatchesCount === 1">Show 1 distinct library rule</span>
                        <span v-else>No library rules matched</span>
                    </label>
                </div>
                <div class="flex flex-row align-items-center gap-2">
                    <Checkbox v-model="showNamespaceChart" inputId="showNamespaceChart" :binary="true" />
                    <label for="showNamespaceChart">Show namespace chart</label>
                </div>
                <div class="flex flex-row align-items-center gap-2">
                    <Checkbox
                        v-model="showColumnFilters"
                        inputId="showColumnFilters"
                        :binary="true"
                        :disabled="showNamespaceChart"
                    />
                    <label for="showColumnFilters">Show column filters</label>
                </div>
            </div>
        </template>
    </Card>
</template>

<script setup>
import { ref, watch } from "vue";
import Checkbox from "primevue/checkbox";

const props = defineProps({
    flavor: {
        type: String,
        required: true
    },
    libraryRuleMatchesCount: {
        type: Number,
        required: true
    }
});

const showCapabilitiesByFunctionOrProcess = ref(false);
const showLibraryRules = ref(false);
const showNamespaceChart = ref(false);
const showColumnFilters = ref(false);

const emit = defineEmits([
    "update:show-capabilities-by-function-or-process",
    "update:show-library-rules",
    "update:show-namespace-chart",
    "update:show-column-filters"
]);

const capabilitiesLabel = props.flavor === "static" ? "Show capabilities by function" : "Show capabilities by process";

watch(showCapabilitiesByFunctionOrProcess, (newValue) => {
    emit("update:show-capabilities-by-function-or-process", newValue);
});

watch(showLibraryRules, (newValue) => {
    emit("update:show-library-rules", newValue);
});

watch(showNamespaceChart, (newValue) => {
    emit("update:show-namespace-chart", newValue);
});

watch(showColumnFilters, (newValue) => {
    emit("update:show-column-filters", newValue);
});
</script>
