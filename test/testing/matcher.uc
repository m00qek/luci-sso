'use strict';

/**
 * Determines if a test should be ignored based on module whitelist and name filters.
 * 
 * @param {object} t - The test object {name, module}.
 * @param {object} options - Execution options {filter, modules}.
 * @returns {boolean} - True if the test should be ignored.
 */
export function should_ignore(t, options) {
    // 1. Module Whitelist Check
    if (type(options.modules) == "array") {
        let found = false;
        for (let m in options.modules) {
            if (t.module == m) {
                found = true;
                break;
            }
        }
        if (!found) return true;
    }

    // 2. Name Filter Check (Assumes options.filter is already a regex object or null)
    if (options.filter && !match(t.name, options.filter)) {
        return true;
    }

    return false;
};
