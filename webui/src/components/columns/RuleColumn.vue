<template>
    <div>
      <template v-if="node.data.type === 'rule'">
        {{ node.data.name }}
      </template>
      <template v-else-if="node.data.type === 'match location'">
        <span class="text-sm font-italic">{{ node.data.name }}</span>
      </template>
      <template v-else-if="node.data.type === 'statement'">-
        <span :class="{ 'text-green-700': node.data.typeValue === 'range', 'font-semibold': node.data.typeValue !== 'range' }">
            {{ node.data.name }}
        </span>
      </template>
      <template v-else-if="node.data.type === 'feature'">
        <span>- {{ node.data.typeValue }}: <span class="text-green-700" style="font-family: monospace;">{{ node.data.name }}</span></span>
      </template>
      <span v-if="node.data.description" class="text-gray-500 text-sm" style="font-size: 90%;">
        = {{ node.data.description }}
      </span>
      <span v-if="node.data.matchCount > 1" class="font-italic">
        ({{ node.data.matchCount }} matches)
      </span>
      <LibraryTag v-if="node.data.lib && node.data.matchCount" />
    </div>
  </template>

  <script setup>
  import { defineProps } from 'vue';
  import LibraryTag from '../misc/LibraryTag.vue';

  defineProps({
    node: {
      type: Object,
      required: true
    }
  });
  </script>
