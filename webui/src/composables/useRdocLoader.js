// useDataLoader.js
import { ref, readonly } from 'vue'
import { useToast } from 'primevue/usetoast'

export function useRdocLoader() {
  const toast = useToast()
  const rdocData = ref(null)
  const isValidVersion = ref(false)

  const MIN_SUPPORTED_VERSION = '7.0.0'

  /**
   * Checks if the loaded rdoc version is supported
   * @param {Object} rdoc - The loaded JSON rdoc data
   * @returns {boolean} - True if version is supported, false otherwise
   */
  const checkVersion = (rdoc) => {
    const version = rdoc.meta.version
    if (version < MIN_SUPPORTED_VERSION) {
      console.error(
        `Version ${version} is not supported. Please use version ${MIN_SUPPORTED_VERSION} or higher.`
      )
      toast.add({
        severity: 'error',
        summary: 'Unsupported Version',
        detail: `Version ${version} is not supported. Please use version ${MIN_SUPPORTED_VERSION} or higher.`,
        life: 5000,
        group: 'bc' // bottom-center
      })
      return false
    }
    return true
  }

  /**
   * Loads JSON rdoc data from various sources
   * @param {File|string|Object} source - File object, URL string, or JSON object
   * @returns {Promise<void>}
   */
  const loadRdoc = async (source) => {
    try {
      let data

      if (source instanceof File) {
        // Load from File
        const text = await source.text()
        data = JSON.parse(text)
      } else if (typeof source === 'string') {
        // Load from URL
        const response = await fetch(source)
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }
        data = await response.json()
      } else if (typeof source === 'object') {
        // Direct JSON object (Preview options)
        data = source
      } else {
        throw new Error('Invalid source type')
      }

      if (checkVersion(data)) {
        rdocData.value = data
        isValidVersion.value = true
        toast.add({
          severity: 'success',
          summary: 'Success',
          detail: 'JSON data loaded successfully',
          life: 3000,
          group: 'bc' // bottom-center
        })
      } else {
        rdocData.value = null
        isValidVersion.value = false
      }
    } catch (error) {
      console.error('Error loading JSON:', error)
      toast.add({
        severity: 'error',
        summary: 'Error',
        detail: error.message,
        life: 3000,
        group: 'bc' // bottom-center
      })
    }
  }

  return {
    rdocData: readonly(rdocData),
    isValidVersion: readonly(isValidVersion),
    loadRdoc
  }
}
