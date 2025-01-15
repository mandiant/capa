/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
