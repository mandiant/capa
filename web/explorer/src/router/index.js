import { createRouter, createWebHashHistory } from "vue-router";
import ImportView from "../views/ImportView.vue";
import NotFoundView from "../views/NotFoundView.vue";

const router = createRouter({
    history: createWebHashHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: "/",
            name: "home",
            component: ImportView
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
