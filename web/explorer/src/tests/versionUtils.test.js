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

import { describe, it, expect } from "vitest";
import { compareVersions, isVersionAtLeast, parseVersion } from "../utils/versionUtils";

describe("parseVersion", () => {
    it("parses dotted numeric versions", () => {
        expect(parseVersion("10.0.0")).toEqual([10, 0, 0]);
        expect(parseVersion("7.0.0")).toEqual([7, 0, 0]);
    });

    it("ignores a leading v", () => {
        expect(parseVersion("v10.0.0")).toEqual([10, 0, 0]);
    });

    it("returns null for empty or non-numeric input", () => {
        expect(parseVersion("")).toBeNull();
        expect(parseVersion("not-a-version")).toBeNull();
        expect(parseVersion(undefined)).toBeNull();
        expect(parseVersion(null)).toBeNull();
    });
});

describe("compareVersions", () => {
    it("compares major versions numerically, not lexicographically", () => {
        // The previous string comparison treated "10.0.0" as less than "7.0.0"
        // because "1" < "7". Numeric comparison must not do that.
        expect("10.0.0" < "7.0.0").toBe(true);
        expect(compareVersions("10.0.0", "7.0.0")).toBeGreaterThan(0);
        expect(compareVersions("7.0.0", "10.0.0")).toBeLessThan(0);
    });

    it("treats equal versions as equal, including different component counts", () => {
        expect(compareVersions("7.0.0", "7.0.0")).toBe(0);
        expect(compareVersions("7", "7.0.0")).toBe(0);
        expect(compareVersions("7.0", "7.0.0")).toBe(0);
    });

    it("orders minor and patch versions correctly", () => {
        expect(compareVersions("7.1.0", "7.0.0")).toBeGreaterThan(0);
        expect(compareVersions("7.0.1", "7.0.0")).toBeGreaterThan(0);
        expect(compareVersions("6.10.0", "7.0.0")).toBeLessThan(0);
        expect(compareVersions("9.9.9", "7.0.0")).toBeGreaterThan(0);
    });

    it("returns null when a version cannot be parsed", () => {
        expect(compareVersions("nope", "7.0.0")).toBeNull();
    });
});

describe("isVersionAtLeast", () => {
    const min = "7.0.0";

    it("accepts the minimum supported version and later releases", () => {
        expect(isVersionAtLeast("7.0.0", min)).toBe(true);
        expect(isVersionAtLeast("7.0.1", min)).toBe(true);
        expect(isVersionAtLeast("9.0.0", min)).toBe(true);
        expect(isVersionAtLeast("10.0.0", min)).toBe(true);
        expect(isVersionAtLeast("11.0.0", min)).toBe(true);
    });

    it("rejects versions below the minimum", () => {
        expect(isVersionAtLeast("6.9.9", min)).toBe(false);
        expect(isVersionAtLeast("6.10.0", min)).toBe(false);
        expect(isVersionAtLeast("0.0.0", min)).toBe(false);
    });

    it("rejects unparseable versions", () => {
        expect(isVersionAtLeast("", min)).toBe(false);
        expect(isVersionAtLeast("abc", min)).toBe(false);
    });
});
