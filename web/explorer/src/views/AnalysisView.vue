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
    <MetadataPanel :data="doc" />
    <SettingsPanel
        :flavor="doc.meta.flavor"
        :library-rule-matches-count="libraryRuleMatchesCount"
        @update:show-capabilities-by-function-or-process="updateShowCapabilitiesByFunctionOrProcess"
        @update:show-library-rules="updateShowLibraryRules"
        @update:show-namespace-chart="updateShowNamespaceChart"
        @update:show-column-filters="updateShowColumnFilters"
    />
    <RuleMatchesTable
        v-if="!showCapabilitiesByFunctionOrProcess && !showNamespaceChart"
        :data="doc"
        :show-library-rules="showLibraryRules"
        :show-column-filters="showColumnFilters"
    />
    <FunctionCapabilities
        v-if="doc.meta.flavor === 'static' && showCapabilitiesByFunctionOrProcess && !showNamespaceChart"
        :data="doc"
        :show-library-rules="showLibraryRules"
        :show-column-filters="showColumnFilters"
    />
    <ProcessCapabilities
        v-else-if="doc.meta.flavor === 'dynamic' && showCapabilitiesByFunctionOrProcess && !showNamespaceChart"
        :data="doc"
        :show-capabilities-by-process="showCapabilitiesByFunctionOrProcess"
        :show-library-rules="showLibraryRules"
        :show-column-filters="showColumnFilters"
    />
    <NamespaceChart v-else-if="showNamespaceChart" :data="doc" />
</template>

<script setup>
import { ref, computed } from "vue";

// Componenets
import MetadataPanel from "@/components/MetadataPanel.vue";
import SettingsPanel from "@/components/SettingsPanel.vue";
import RuleMatchesTable from "@/components/RuleMatchesTable.vue";
import FunctionCapabilities from "@/components/FunctionCapabilities.vue";
import ProcessCapabilities from "@/components/ProcessCapabilities.vue";
import NamespaceChart from "@/components/NamespaceChart.vue";

// Import loaded rdoc
import { rdocStore } from "@/store/rdocStore";
const doc = rdocStore.data.value;

// Viewing options
const showCapabilitiesByFunctionOrProcess = ref(false);
const showLibraryRules = ref(false);
const showNamespaceChart = ref(false);
const showColumnFilters = ref(false);

// Count library rules
const libraryRuleMatchesCount = computed(() => {
    if (!doc || !doc.rules) return 0;
    return Object.values(rdocStore.data.value.rules).filter((rule) => rule.meta.lib).length;
});

// Event handlers to update variables
const updateShowCapabilitiesByFunctionOrProcess = (value) => {
    showCapabilitiesByFunctionOrProcess.value = value;
};

const updateShowLibraryRules = (value) => {
    showLibraryRules.value = value;
};

const updateShowNamespaceChart = (value) => {
    showNamespaceChart.value = value;
};

const updateShowColumnFilters = (value) => {
    showColumnFilters.value = value;
};
</script>
