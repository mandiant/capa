<template>
  <div class="flex flex-column align-items-center">
    <div class="text-center">
      <h1>
        <img src="../assets/images/logo-full.png" alt="Capa: identify program capabilities" />
        <h6 class="font-medium" style="color: rgb(176, 26, 26)">
          capa: identify program capabilities
        </h6>
      </h1>
    </div>
    <div>
      <p class="text-xl max-w-75rem" style="max-width: 75ch">
        Capa-WebUI is a web-based tool for exploring the capabilities identified in a program. It
        can be used to search and display the rule matches in different viewing modes.
      </p>
    </div>
    <div class="flex justify-content-center w-full mb-3 gap-4">
      <Button label="Help" @click="openDialog('help')" icon="pi pi-info-circle" outlined />
      <Button label="Changelog" @click="openDialog('changelog')" icon="pi pi-history" outlined />
    </div>
  </div>

  <Dialog v-model:visible="helpDialogVisible" header="Help" modal>
    <p>TODO: Help instruction to walk through users how generate a capa report.</p>
  </Dialog>

  <Dialog v-model:visible="changelogDialogVisible" header="Changelog" modal>
    <p>TODO: Add major changes to the tool here.</p>
  </Dialog>
</template>

<script setup>
import { ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'

const helpDialogVisible = ref(false)
const changelogDialogVisible = ref(false)

const openDialog = (type) => {
  if (type === 'help') {
    helpDialogVisible.value = true
  } else if (type === 'changelog') {
    changelogDialogVisible.value = true
  }
}
</script>
