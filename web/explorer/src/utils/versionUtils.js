/**
 * Copyright 2026 Google LLC
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

/**
 * Parse a dotted version string into numeric components.
 * A leading "v" is ignored. Parsing stops at the first component that does not
 * start with a digit, so PEP 440 suffixes such as "10.0.0.dev0" or "10.0.0.post1"
 * are treated as [10, 0, 0]. Non-numeric suffixes inside a component are ignored
 * by parseInt, so "10.0.0-rc1" and "10.0.0+dev" are also treated as [10, 0, 0].
 * This means pre-releases compare equal to their release, which is fine for a
 * minimum-version check.
 * @param {string} version
 * @returns {number[]|null} Version parts, or null if the string cannot be parsed.
 */
export const parseVersion = (version) => {
    if (version === undefined || version === null) {
        return null;
    }
    const raw = String(version).trim().replace(/^v/i, "");
    if (raw === "") {
        return null;
    }
    const parts = [];
    for (const part of raw.split(".")) {
        if (!/^\d/.test(part)) {
            break;
        }
        parts.push(parseInt(part, 10));
    }
    if (parts.length === 0) {
        return null;
    }
    return parts;
};

/**
 * Compare two dotted version strings numerically.
 * @param {string} a
 * @param {string} b
 * @returns {number|null} Negative if a < b, 0 if equal, positive if a > b.
 *   Returns null if either version cannot be parsed.
 */
export const compareVersions = (a, b) => {
    const pa = parseVersion(a);
    const pb = parseVersion(b);
    if (pa === null || pb === null) {
        return null;
    }
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const da = pa[i] ?? 0;
        const db = pb[i] ?? 0;
        if (da !== db) {
            return da - db;
        }
    }
    return 0;
};

/**
 * Return true if `version` is greater than or equal to `minVersion`.
 * Unparseable versions are treated as unsupported.
 * @param {string} version
 * @param {string} minVersion
 * @returns {boolean}
 */
export const isVersionAtLeast = (version, minVersion) => {
    const cmp = compareVersions(version, minVersion);
    return cmp !== null && cmp >= 0;
};
