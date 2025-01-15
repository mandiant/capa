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
    <div ref="chartRef" class="w-screen h-screen"></div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import Plotly from "plotly.js-dist";

const props = defineProps({
    data: {
        type: Object,
        required: true
    }
});

const chartRef = ref(null);

const createSunburstData = (rules) => {
    const data = {
        ids: [],
        labels: [],
        parents: [],
        values: []
    };

    const addNamespace = (namespace, value) => {
        const parts = namespace.split("/");
        let currentId = "";
        let parent = "";

        parts.forEach((part) => {
            currentId = currentId ? `${currentId}/${part}` : part;

            if (!data.ids.includes(currentId)) {
                data.ids.push(currentId);
                data.labels.push(part);
                data.parents.push(parent);
                data.values.push(0);
            }

            const valueIndex = data.ids.indexOf(currentId);
            data.values[valueIndex] += value;

            parent = currentId;
        });

        return parent;
    };

    Object.entries(rules).forEach(([ruleName, rule]) => {
        if (rule.meta.lib) return; // Skip library rules

        const namespace = rule.meta.namespace || "root";
        const parent = addNamespace(namespace, rule.matches.length);

        // Add the rule itself
        data.ids.push(ruleName);
        data.labels.push(rule.meta.name);
        data.parents.push(parent);
        data.values.push(rule.matches.length);
    });

    return data;
};

const renderChart = () => {
    if (!chartRef.value) return;

    const sunburstData = createSunburstData(props.data.rules);

    const layout = {
        margin: { l: 0, r: 0, b: 0, t: 0 },
        sunburstcolorway: [
            "#636efa",
            "#EF553B",
            "#00cc96",
            "#ab63fa",
            "#19d3f3",
            "#e763fa",
            "#FECB52",
            "#FFA15A",
            "#FF6692",
            "#B6E880"
        ],
        extendsunburstcolorway: true
    };

    const config = {
        responsive: true
    };

    Plotly.newPlot(
        chartRef.value,
        [
            {
                type: "sunburst",
                ids: sunburstData.ids,
                labels: sunburstData.labels,
                parents: sunburstData.parents,
                values: sunburstData.values,
                outsidetextfont: { size: 20, color: "#377eb8" },
                leaf: { opacity: 0.4 },
                marker: { line: { width: 2 } },
                branchvalues: "total"
            }
        ],
        layout,
        config
    );

    return sunburstData;
};

onMounted(() => {
    renderChart();
});
</script>
