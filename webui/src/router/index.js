import { createRouter, createWebHistory } from 'vue-router'
import ImportView from '../views/ImportView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: ImportView
    }
  ]
})

export default router
