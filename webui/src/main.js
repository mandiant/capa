import 'primeicons/primeicons.css'
import './assets/main.css'

import 'highlight.js/styles/default.css'
import 'primeflex/primeflex.css'
import 'primeflex/themes/primeone-light.css'

import 'highlight.js/lib/common'
import hljsVuePlugin from '@highlightjs/vue-plugin'

import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import Ripple from 'primevue/ripple'
import Aura from '@primevue/themes/aura'
import App from './App.vue'
import MenuBar from 'primevue/menubar'
import Card from 'primevue/card'
import Panel from 'primevue/panel'
import Column from 'primevue/column'
import Checkbox from 'primevue/checkbox'
import FloatLabel from 'primevue/floatlabel'
import Tooltip from 'primevue/tooltip'
import Divider from 'primevue/divider'
import ToastService from 'primevue/toastservice'
import Toast from 'primevue/toast'
import router from './router'

import { definePreset } from '@primevue/themes'

const Noir = definePreset(Aura, {
  semantic: {
    primary: {
      50: '{zinc.50}',
      100: '{zinc.100}',
      200: '{zinc.200}',
      300: '{zinc.300}',
      400: '{zinc.400}',
      500: '{zinc.500}',
      600: '{zinc.600}',
      700: '{zinc.700}',
      800: '{zinc.800}',
      900: '{zinc.900}',
      950: '{zinc.950}'
    },
    colorScheme: {
      light: {
        primary: {
          color: '{slate.700}',
          inverseColor: '#ffffff',
          hoverColor: '{zinc.900}',
          activeColor: '{zinc.800}'
        },
        highlight: {
          background: '{zinc.950}',
          focusBackground: '{zinc.700}',
          color: '#ffffff',
          focusColor: '#ffffff'
        }
      },
      dark: {
        primary: {
          color: '{zinc.50}',
          inverseColor: '{zinc.950}',
          hoverColor: '{zinc.100}',
          activeColor: '{zinc.200}'
        },
        highlight: {
          background: 'rgba(250, 250, 250, .16)',
          focusBackground: 'rgba(250, 250, 250, .24)',
          color: 'rgba(255,255,255,.87)',
          focusColor: 'rgba(255,255,255,.87)'
        }
      }
    }
  }
})

const app = createApp(App)

app.use(router)
app.use(hljsVuePlugin)

app.use(PrimeVue, {
  theme: {
    preset: Noir,
    options: {
      darkModeSelector: 'light'
    }
  },
  ripple: true
})
app.use(ToastService)

app.directive('tooltip', Tooltip)
app.directive('ripple', Ripple)

app.component('Card', Card)
app.component('Divider', Divider)
app.component('Toast', Toast)
app.component('Panel', Panel)
app.component('MenuBar', MenuBar)
app.component('Checkbox', Checkbox)
app.component('FloatLabel', FloatLabel)
app.component('Column', Column)

app.mount('#app')
