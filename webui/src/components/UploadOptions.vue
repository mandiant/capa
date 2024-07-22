<template>
  <Card>
    <template #content>
      <div class="flex flex-wrap align-items-center justify-content-center gap-3">
        <div class="flex-grow-1 flex align-items-center justify-content-center">
          <FileUpload
            mode="basic"
            name="model[]"
            accept="application/json"
            :max-file-size="5000000"
            :auto="true"
            :custom-upload="true"
            choose-label="Upload from local"
            @uploader="$emit('load-from-local', $event)"
          />
        </div>

        <Divider layout="vertical" class="hidden-mobile">
          <b>OR</b>
        </Divider>
        <Divider layout="horizontal" class="visible-mobile" align="center">
          <b>OR</b>
        </Divider>

        <div class="flex-grow-1 flex align-items-center justify-content-center gap-2">
          <FloatLabel>
            <InputText id="url" type="text" v-model="loadURL" />
            <label for="url">Load from URL</label>
          </FloatLabel>
          <Button
            icon="pi pi-arrow-right"
            @click="$emit('load-from-url', loadURL)"
            :disabled="!loadURL"
          />
        </div>

        <Divider layout="vertical" class="hidden-mobile">
          <b>OR</b>
        </Divider>
        <Divider layout="horizontal" class="visible-mobile" align="center">
          <b>OR</b>
        </Divider>

        <div class="flex-grow-1 flex align-items-center justify-content-center">
          <Button label="Preview Static" @click="$emit('load-demo-static')" class="p-button" />
        </div>

        <Divider layout="vertical" class="hidden-mobile">
          <b>OR</b>
        </Divider>
        <Divider layout="horizontal" class="visible-mobile" align="center">
          <b>OR</b>
        </Divider>

        <div class="flex-grow-1 flex align-items-center justify-content-center">
          <Button label="Preview Dynamic" @click="$emit('load-demo-dynamic')" class="p-button" />
        </div>
      </div>
    </template>
  </Card>
</template>

<script setup>
import { ref } from 'vue'
import Card from 'primevue/card'
import FileUpload from 'primevue/fileupload'
import Divider from 'primevue/divider'
import FloatLabel from 'primevue/floatlabel'
import InputText from 'primevue/inputtext'
import Button from 'primevue/button'

const loadURL = ref('')

defineEmits(['load-from-local', 'load-from-url', 'load-demo-static', 'load-demo-dynamic'])
</script>

<style scoped>
@media screen and (min-width: 769px) {
  .hidden-mobile {
    display: flex !important;
  }
  .visible-mobile {
    display: none !important;
  }
}

@media screen and (max-width: 768px) {
  .hidden-mobile {
    display: none !important;
  }
  .visible-mobile {
    display: flex !important;
  }
}
</style>
