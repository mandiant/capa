<template>
  <Card>
    <template #content>
      <div class="flex align-items-center flex-row gap-3">
        <div class="flex flex-row align-items-center gap-2">
          <Checkbox
            v-model="showCapabilitiesByFunctionOrProcess"
            inputId="showCapabilitiesByFunctionOrProcess"
            :binary="true"
          />
          <label for="showCapabilitiesByFunctionOrProcess">{{ capabilitiesLabel }}</label>
        </div>
        <div class="flex flex-row align-items-center gap-2">
          <Checkbox v-model="showLibraryRules" inputId="showLibraryRules" :binary="true" />
          <label for="showLibraryRules">
            <span v-if="libraryRuleMatchesCount > 1">
              Show {{ libraryRuleMatchesCount }} library rule matches
            </span>
            <span v-else>Show 1 library rule match</span>
          </label>
        </div>
      </div>
    </template>
  </Card>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import Checkbox from 'primevue/checkbox'

const props = defineProps({
  flavor: {
    type: String,
    required: true
  },
  libraryRuleMatchesCount: {
    type: Number,
    required: true
  }
})

const showCapabilitiesByFunctionOrProcess = ref(false)
const showLibraryRules = ref(false)

const emit = defineEmits([
  'update:show-capabilities-by-function-or-process',
  'update:show-library-rules'
])

const capabilitiesLabel = computed(() => {
  return props.flavor === 'static'
    ? 'Show capabilities by function'
    : 'Show capabilities by process'
})

watch(showCapabilitiesByFunctionOrProcess, (newValue) => {
  emit('update:show-capabilities-by-function-or-process', newValue)
})

watch(showLibraryRules, (newValue) => {
  emit('update:show-library-rules', newValue)
})
</script>
