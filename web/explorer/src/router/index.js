import { createRouter, createWebHashHistory } from "vue-router";
import ImportView from "@/views/ImportView.vue";
import NotFoundView from "@/views/NotFoundView.vue";
import AnalysisView from "@/views/AnalysisView.vue";

import { rdocStore } from "@/store/rdocStore";

const router = createRouter({
    history: createWebHashHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: "/",
            name: "home",
            component: ImportView
        },
        {
            path: "/analysis",
            name: "analysis",
            component: AnalysisView,
            beforeEnter: (to, from, next) => {
                if (rdocStore.data.value === null) {
                    // No rdoc loaded, redirect to home page
                    next({ name: "home" });
                } else {
                    // rdoc is loaded, proceed to analysis page
                    next();
                }
            }
        },
        // 404 Route - This should be the last route
        {
            path: "/:pathMatch(.*)*",
            name: "NotFound",
            component: NotFoundView
        }
    ]
});

export default router;
