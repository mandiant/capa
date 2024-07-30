import { createRouter, createWebHashHistory } from 'vue-router'
import ImportView from '../views/ImportView.vue'

const router = createRouter({
  history: createWebHashHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: ImportView
    }
  ]
})

export default router
