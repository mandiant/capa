<script setup>
import { ref, computed, onMounted } from 'vue'
import DescriptionPanel from '../components/DescriptionPanel.vue'
import UploadOptions from '../components/UploadOptions.vue'
import MetadataPanel from '../components/MetadataPanel.vue'
import RuleMatchesTable from '../components/RuleMatchesTable.vue'
import FunctionCapabilities from '../components/FunctionCapabilities.vue'
import ProcessCapabilities from '../components/ProcessCapabilities.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import Toast from 'primevue/toast'

import demoRdocStatic from '../../../tests/data/rd/al-khaser_x64.exe_.json'
import demoRdocDynamic from '../../../tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json'

import { useRdocLoader } from '../composables/useRdocLoader'

const { rdocData, isValidVersion, loadRdoc } = useRdocLoader()

const showCapabilitiesByFunctionOrProcess = ref(false)
const showLibraryRules = ref(false)

const flavor = computed(() => rdocData.value?.meta.flavor)

const libraryRuleMatchesCount = computed(() => {
  if (!rdocData.value || !rdocData.value.rules) return 0
  return Object.values(rdocData.value.rules).filter((rule) => rule.meta.lib).length
})

const updateShowCapabilitiesByFunctionOrProcess = (value) => {
  showCapabilitiesByFunctionOrProcess.value = value
}

const updateShowLibraryRules = (value) => {
  showLibraryRules.value = value
}

const loadFromLocal = (event) => {
  const file = event.files[0]
  loadRdoc(file)
}

const loadFromURL = (url) => {
  loadRdoc(url)
}

const loadDemoDataStatic = () => {
  loadRdoc(demoRdocStatic)
}

const loadDemoDataDynamic = () => {
  loadRdoc(demoRdocDynamic)
}

onMounted(() => {
  const urlParams = new URLSearchParams(window.location.search)
  const rdocURL = urlParams.get('rdoc')
  if (rdocURL) {
    loadFromURL(rdocURL)
  }
})
</script>

<template>
  <!-- When rdocData is set to null or version is not valid, show the description panel and upload options. -->
  <Panel v-if="!rdocData || !isValidVersion">
    <DescriptionPanel />
    <UploadOptions
      @load-from-local="loadFromLocal"
      @load-from-url="loadFromURL"
      @load-demo-static="loadDemoDataStatic"
      @load-demo-dynamic="loadDemoDataDynamic"
    />
  </Panel>

  <!-- When rdocData is set and version is valid, show the metadata, settings panel, rule matches table,
  function capabilities or process capabilities. -->
  <Toast position="bottom-center" group="bc" />
  <template v-if="rdocData && isValidVersion">
    <MetadataPanel :data="rdocData" />
    <SettingsPanel
      :flavor="flavor"
      :library-rule-matches-count="libraryRuleMatchesCount"
      @update:show-capabilities-by-function-or-process="updateShowCapabilitiesByFunctionOrProcess"
      @update:show-library-rules="updateShowLibraryRules"
    />

    <RuleMatchesTable
      v-if="!showCapabilitiesByFunctionOrProcess"
      :data="rdocData"
      :show-library-rules="showLibraryRules"
    />
    <FunctionCapabilities
      v-if="flavor === 'static' && showCapabilitiesByFunctionOrProcess"
      :data="rdocData"
      :show-library-rules="showLibraryRules"
    />
    <ProcessCapabilities
      v-else-if="flavor === 'dynamic' && showCapabilitiesByFunctionOrProcess"
      :data="rdocData"
      :show-capabilities-by-process="showCapabilitiesByFunctionOrProcess"
      :show-library-rules="showLibraryRules"
    />
  </template>
</template>
