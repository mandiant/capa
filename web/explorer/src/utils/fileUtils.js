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
