import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig(({ command, mode }) => {
  const isBundle = mode === 'bundle'

  return {
    base: isBundle ? '/' : '/capa/',
    plugins: isBundle ? [vue(), viteSingleFile()] : [vue()]
  }
})
