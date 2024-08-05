import pako from "pako";

/**
 * Checks if the given file is gzipped
 * @param {File} file - The file to check
 * @returns {Promise<boolean>} - True if the file is gzipped, false otherwise
 */
export const isGzipped = async (file) => {
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);
    return uint8Array[0] === 0x1f && uint8Array[1] === 0x8b;
};

/**
 * Decompresses a gzipped file
 * @param {File} file - The gzipped file to decompress
 * @returns {Promise<string>} - The decompressed file content as a string
 */
export const decompressGzip = async (file) => {
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);
    const decompressed = pako.inflate(uint8Array, { to: "string" });
    return decompressed;
};

/**
 * Reads a file as text
 * @param {File} file - The file to read
 * @returns {Promise<string>} - The file content as a string
 */
export const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => resolve(event.target.result);
        reader.onerror = (error) => reject(error);
        reader.readAsText(file);
    });
};
