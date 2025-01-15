<!--
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

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
