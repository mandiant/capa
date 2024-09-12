<template>
    <div class="cursor-default">
        <!-- example node: "parse PE headers (2 matches) lib" -->
        <template v-if="node.data.type === 'rule'">
            <div>
                <span>{{ node.data.name }}</span>
                <span v-if="node.data.matchCount > 1" class="font-italic match-count">
                    ({{ node.data.matchCount }} matches)
                </span>
                <LibraryTag v-if="node.data.lib && node.data.matchCount" />
            </div>
        </template>

        <!-- example node: "basic block @ 0x401000" or "explorer.exe" -->
        <template v-else-if="node.data.type === 'match location'">
            <span class="text-sm font-monospace text-xs">{{ node.data.name }}</span>
        </template>

        <!-- example node: "- or", "- and" -->
        <template v-else-if="node.data.type === 'statement'">
            -
            <span
                :class="{
                    'text-green-700': node.data.typeValue === 'range',
                    'font-semibold': node.data.typeValue !== 'range'
                }"
            >
                {{ node.data.name }}
            </span>
        </template>

        <!-- example node: "- api: GetProcAddress", "- regex: .*\\.exe" -->
        <template v-else-if="node.data.type === 'feature'">
            <span>
                - {{ node.data.typeValue }}:
                <span
                    :class="{ 'text-green-700': node.data.typeValue !== 'regex' }"
                    class="font-monospace"
                    v-tooltip.top="{
                        value: getTooltipContent(node.data),
                        showDelay: 1000,
                        hideDelay: 300
                    }"
                >
                    {{ node.data.name }}
                </span>
            </span>
        </template>

        <!-- example node: "- malware.exe" (these are the captures (i.e. children nodes) of regex nodes) -->
        <template v-else-if="node.data.type === 'regex-capture'">
            -
            <span class="text-green-700 font-monospace">{{ node.data.name }}</span>
        </template>

        <!-- example node: "exit(0) -> 0" (if the node type is call-info, we highlight node.data.name.callInfo) -->
        <template v-else-if="node.data.type === 'call-info'">
            <highlightjs lang="c" :code="node.data.name.callInfo" class="text-xs" />
        </template>

        <!-- example node: " = IMAGE_NT_SIGNATURE (PE)" -->
        <span v-if="node.data.description" class="text-gray-500 text-sm" style="font-size: 90%">
            = {{ node.data.description }}
        </span>
    </div>
</template>

<script setup>
import LibraryTag from "@/components/misc/LibraryTag.vue";

defineProps({
    node: {
        type: Object,
        required: true
    }
});

const getTooltipContent = (data) => {
    if (data.typeValue === "number" || data.typeValue === "offset") {
        const decimalValue = parseInt(data.name, 16);
        return `Decimal: ${decimalValue}`;
    }
    return null;
};
</script>
