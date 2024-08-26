import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { viteSingleFile } from "vite-plugin-singlefile";
import { fileURLToPath, URL } from "node:url";

export default defineConfig(({ mode }) => {
    const isBundle = mode === "bundle";

    return {
        base: "./",
        plugins: isBundle ? [vue(), viteSingleFile()] : [vue()],
        resolve: {
            alias: {
                "@": fileURLToPath(new URL("src", import.meta.url)),
                "@testfiles": fileURLToPath(new URL("../../tests/data", import.meta.url))
            }
        },
        assetsInclude: ["**/*.gz"]
    };
});
