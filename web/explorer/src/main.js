import "primeicons/primeicons.css";
import "./assets/main.css";

import "highlight.js/styles/default.css";
import "primeflex/primeflex.css";
import "primeflex/themes/primeone-light.css";

import "highlight.js/lib/common";
import hljsVuePlugin from "@highlightjs/vue-plugin";

import { createApp } from "vue";
import PrimeVue from "primevue/config";
import Ripple from "primevue/ripple";
import Aura from "@primevue/themes/aura";
import App from "./App.vue";
import MenuBar from "primevue/menubar";
import Card from "primevue/card";
import Panel from "primevue/panel";
import Column from "primevue/column";
import Checkbox from "primevue/checkbox";
import FloatLabel from "primevue/floatlabel";
import Tooltip from "primevue/tooltip";
import Divider from "primevue/divider";
import ContextMenu from "primevue/contextmenu";
import ToastService from "primevue/toastservice";
import Toast from "primevue/toast";
import router from "./router";

import { definePreset } from "@primevue/themes";

const Noir = definePreset(Aura, {
    semantic: {
        colorScheme: {
            light: {
                primary: {
                    color: "{slate.800}",
                    inverseColor: "#ffffff",
                    hoverColor: "{sky.800}",
                    activeColor: "{sky.800}"
                }
            }
        }
    }
});

const app = createApp(App);

app.use(router);
app.use(hljsVuePlugin);

app.use(PrimeVue, {
    theme: {
        preset: Noir,
        options: {
            darkModeSelector: "light"
        }
    },
    ripple: true
});
app.use(ToastService);

app.directive("tooltip", Tooltip);
app.directive("ripple", Ripple);

app.component("Card", Card);
app.component("Divider", Divider);
app.component("Toast", Toast);
app.component("Panel", Panel);
app.component("MenuBar", MenuBar);
app.component("Checkbox", Checkbox);
app.component("FloatLabel", FloatLabel);
app.component("Column", Column);
app.component("ContextMenu", ContextMenu);

app.mount("#app");
