import * as c from 'testing.colors';
import { STATUS } from 'testing.status';

const indent = "  ";

export function on_suite_start(name, options) {
    if (name) {
        print(`\n${c.color(c.COLORS.BOLD + c.COLORS.CYAN, "● Suite: " + name)}\n`);
        if (type(options.modules) == "array") {
            print(`${indent}${c.color(c.COLORS.CYAN, "Modules:")} ${join(", ", options.modules)}\n`);
        }
        if (options.filter) {
            print(`${indent}${c.color(c.COLORS.CYAN, "Matching:")} /${options.filter}/\n`);
        }
        // Always a blank line before the results
        print("\n");
    }
};

export function on_test_result(test, result) {
    if (result.status == STATUS.SKIP) {
        print(`${indent}${c.color(c.COLORS.YELLOW, "[SKIP]")} ${test.name}\n`);
        return;
    }

    if (result.status == STATUS.PASS) {
        print(`${indent}${c.color(c.COLORS.GREEN, "[PASS]")} ${test.name}\n`);
    } else {
        let label = (result.status == STATUS.FAIL) ? c.color(c.COLORS.RED, "[FAIL]") : c.color(c.COLORS.BRED, "[ERR]");
        print(`${indent}${label} ${test.name}\n${indent}       ${result.failure || result.error}\n`);
    }
};

export function on_suite_end(stats) {
    print(`\n${indent}${c.color(c.COLORS.GREEN, stats.passed_count)} successes / ` +
          `${c.color(c.COLORS.RED, stats.failed_count)} failures / ` +
          `${c.color(c.COLORS.BRED, stats.errors_count)} errors / ` +
          `${c.color(c.COLORS.YELLOW, stats.skipped_count)} skipped / ` +
          `${c.color(c.COLORS.CYAN, stats.filtered_count)} ignored`);

    let time_str = (stats.duration < 1.0) 
        ? sprintf("%d ms", stats.duration * 1000) 
        : sprintf("%.3f seconds", stats.duration);

    print(` (${c.color(c.COLORS.BOLD, time_str)})\n`);
};
