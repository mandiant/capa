import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { viteSingleFile } from "vite-plugin-singlefile";
import { fileURLToPath, URL } from "node:url";

// eslint-disable-next-line no-unused-vars
export default defineConfig(({ command, mode }) => {
    const isBundle = mode === "bundle";

    return {
        base: "./",
        plugins: isBundle ? [vue(), viteSingleFile()] : [vue()],
        resolve: {
            alias: {
                "@": fileURLToPath(new URL("src", import.meta.url)),
                "@testfiles": fileURLToPath(new URL("../../tests/data", import.meta.url))
            }
        }
    };
});
