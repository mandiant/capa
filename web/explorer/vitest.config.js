import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
    plugins: [vue()],
    test: {
        globals: true,
        environment: "jsdom",
        exclude: ["node_modules", "dist", ".idea", ".git", ".cache"],
        include: ["src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}"]
    }
});
