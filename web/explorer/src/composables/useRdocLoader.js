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

import { useToast } from "primevue/usetoast";
import { isGzipped, decompressGzip, readFileAsText } from "@/utils/fileUtils";

const VT_REANALYZE_SUGGESTION =
    " If this is a VirusTotal or similar link, the file may need to be reanalyzed. Try again later.";

export function useRdocLoader() {
    const toast = useToast();
    const MIN_SUPPORTED_VERSION = "7.0.0";

    /**
     * Displays a toast notification.
     * @param {string} severity - The severity level of the notification
     * @param {string} summary - The title of the notification.
     * @param {string} detail - The detailed message of the notification.
     * @returns {void}
     */
    const showToast = (severity, summary, detail) => {
        toast.add({ severity, summary, detail, life: 3000, group: "bc" }); // bc: bottom-center
    };

    /**
     * Validates that the parsed object has the expected result document schema.
     * @param {Object} rdoc - The parsed JSON data.
     * @returns {{ valid: boolean, message?: string }} Validation result with an optional error message.
     */
    const validateRdocSchema = (rdoc) => {
        const isInvalidObject = (v) => !v || typeof v !== "object" || Array.isArray(v);

        if (isInvalidObject(rdoc)) {
            return { valid: false, message: "Invalid JSON: expected an object." };
        }
        if (isInvalidObject(rdoc.meta)) {
            return { valid: false, message: "Invalid result document: missing or invalid 'meta' field." };
        }
        if (rdoc.meta.version === undefined) {
            return { valid: false, message: "Invalid result document: missing 'meta.version'." };
        }
        if (isInvalidObject(rdoc.meta.analysis)) {
            return { valid: false, message: "Invalid result document: missing or invalid 'meta.analysis'." };
        }
        if (isInvalidObject(rdoc.meta.analysis.layout)) {
            return { valid: false, message: "Invalid result document: missing or invalid 'meta.analysis.layout'." };
        }
        if (isInvalidObject(rdoc.meta.analysis.feature_counts)) {
            return {
                valid: false,
                message: "Invalid result document: missing or invalid 'meta.analysis.feature_counts'."
            };
        }
        const fc = rdoc.meta.analysis.feature_counts;
        // Allow file-scoped-only documents (no functions/processes arrays).
        // If present, functions and processes must be arrays.
        if (fc.functions !== undefined && !Array.isArray(fc.functions)) {
            return {
                valid: false,
                message:
                    "Invalid result document: 'meta.analysis.feature_counts.functions' must be an array when present."
            };
        }
        if (fc.processes !== undefined && !Array.isArray(fc.processes)) {
            return {
                valid: false,
                message:
                    "Invalid result document: 'meta.analysis.feature_counts.processes' must be an array when present."
            };
        }
        if (isInvalidObject(rdoc.rules)) {
            return { valid: false, message: "Invalid result document: missing or invalid 'rules' field." };
        }
        return { valid: true };
    };

    /**
     * Checks if the version of the loaded data is supported.
     * @param {Object} rdoc - The loaded JSON data containing version information.
     * @returns {boolean} True if the version is supported, false otherwise.
     */
    const checkVersion = (rdoc) => {
        const version = rdoc.meta.version;
        if (version < MIN_SUPPORTED_VERSION) {
            showToast(
                "error",
                "Unsupported Version",
                `Version ${version} is not supported. Please use version ${MIN_SUPPORTED_VERSION} or higher.`
            );
            return false;
        }
        return true;
    };

    /**
     * Processes the content of a file or blob.
     * @param {File|Blob} blob - The file or blob to process.
     * @returns {Promise<Object>} A promise that resolves to the parsed JSON data.
     * @throws {Error} If the content cannot be parsed as JSON.
     */
    const processBlob = async (blob) => {
        const content = (await isGzipped(blob)) ? await decompressGzip(blob) : await readFileAsText(blob);
        return JSON.parse(content);
    };

    /**
     * Fetches data from a URL.
     * @param {string} url - The URL to fetch data from.
     * @returns {Promise<Blob>} A promise that resolves to the fetched data as a Blob.
     * @throws {Error} If the fetch request fails.
     */
    const fetchFromUrl = async (url) => {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.blob();
    };

    /**
     * Loads and processes RDOC data from various sources.
     * @param {string|File|Object} source - The source of the RDOC data. Can be a URL string, a File object, or a JSON object.
     * @returns {Promise<Object|null>} A promise that resolves to the processed RDOC data, or null if processing fails.
     */
    const loadRdoc = async (source) => {
        const isUrl = typeof source === "string";

        try {
            let data;

            if (isUrl) {
                const blob = await fetchFromUrl(source);
                data = await processBlob(blob);
            } else if (source instanceof File) {
                data = await processBlob(source);
            } else {
                throw new Error("Invalid source type");
            }

            const validation = validateRdocSchema(data);
            if (!validation.valid) {
                let detail = validation.message;
                if (isUrl) {
                    detail += VT_REANALYZE_SUGGESTION;
                }
                showToast("error", "Invalid result document", detail);
                return null;
            }

            if (checkVersion(data)) {
                showToast("success", "Success", "JSON data loaded successfully");
                return data;
            }
        } catch (error) {
            console.error("Error loading JSON:", error);
            let detail = error.message;
            if (isUrl && (error instanceof SyntaxError || error.message.includes("JSON"))) {
                detail += VT_REANALYZE_SUGGESTION;
            }
            showToast("error", "Failed to process the file", detail);
        }
        return null;
    };

    return { loadRdoc };
}
