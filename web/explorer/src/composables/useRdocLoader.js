import { useToast } from "primevue/usetoast";
import { isGzipped, decompressGzip, readFileAsText } from "@/utils/fileUtils";

export function useRdocLoader() {
    const toast = useToast();
    const MIN_SUPPORTED_VERSION = "7.0.0";

    /**
     * Checks if the loaded rdoc version is supported
     * @param {Object} rdoc - The loaded JSON rdoc data
     * @returns {boolean} - True if version is supported, false otherwise
     */
    const checkVersion = (rdoc) => {
        const version = rdoc.meta.version;
        if (version < MIN_SUPPORTED_VERSION) {
            console.error(
                `Version ${version} is not supported. Please use version ${MIN_SUPPORTED_VERSION} or higher.`
            );
            toast.add({
                severity: "error",
                summary: "Unsupported Version",
                detail: `Version ${version} is not supported. Please use version ${MIN_SUPPORTED_VERSION} or higher.`,
                life: 5000,
                group: "bc" // bottom-center
            });
            return false;
        }
        return true;
    };

    /**
     * Loads JSON rdoc data from various sources
     * @param {File|string|Object} source - File object, URL string, or JSON object
     * @returns {Promise<void>}
     */
    const loadRdoc = async (source) => {
        try {
            let data;

            if (typeof source === "string") {
                // Load from URL
                const response = await fetch(source);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                data = await response.json();
            } else if (source instanceof File) {
                let fileContent;
                if (await isGzipped(source)) {
                    fileContent = await decompressGzip(source);
                } else {
                    fileContent = await readFileAsText(source);
                }
                data = JSON.parse(fileContent);
            } else if (typeof source === "object") {
                // Direct JSON object (Preview options)
                data = source;
            } else {
                throw new Error("Invalid source type");
            }

            if (checkVersion(data)) {
                toast.add({
                    severity: "success",
                    summary: "Success",
                    detail: "JSON data loaded successfully",
                    life: 3000,
                    group: "bc" // bottom-center
                });
                return data;
            }
        } catch (error) {
            console.error("Error loading JSON:", error);
            toast.add({
                severity: "error",
                summary: "Error",
                detail: "Failed to process the file. Please ensure it's a valid JSON or gzipped JSON file.",
                life: 3000,
                group: "bc" // bottom-center
            });
        }
        return null;
    };

    return {
        loadRdoc
    };
}
