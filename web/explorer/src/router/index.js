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
                // check if rdoc is loaded
                if (rdocStore.data.value !== null) {
                    // rdocStore.data already contains the rdoc json - continue
                    next();
                } else {
                    // rdoc is not loaded, check if the rdoc query param is set in the URL
                    const rdocUrl = to.query.rdoc;
                    if (rdocUrl) {
                        // query param is set - try to load the rdoc from the homepage
                        next({ name: "home", query: { rdoc: rdocUrl } });
                    } else {
                        // no query param is set - go back home
                        next({ name: "home" });
                    }
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
