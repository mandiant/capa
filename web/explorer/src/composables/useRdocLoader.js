import { useToast } from "primevue/usetoast";
import { isGzipped, decompressGzip, readFileAsText } from "@/utils/fileUtils";

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
        try {
            let data;

            if (typeof source === "string") {
                // Load from URL
                const blob = await fetchFromUrl(source);
                data = await processBlob(blob);
            } else if (source instanceof File) {
                // Load from local
                data = await processBlob(source);
            } else {
                throw new Error("Invalid source type");
            }

            if (checkVersion(data)) {
                showToast("success", "Success", "JSON data loaded successfully");
                return data;
            }
        } catch (error) {
            console.error("Error loading JSON:", error);
            showToast("error", "Failed to process the file", error.message);
        }
        return null;
    };

    return { loadRdoc };
}
