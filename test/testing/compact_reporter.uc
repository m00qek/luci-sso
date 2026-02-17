import * as c from 'testing.colors';
import { STATUS } from 'testing.status';

let first_result = true;
let column_count = 0;
const MAX_COLS = 80;
const INDENT = "  ";

export function on_suite_start(name, options) {
    if (name) {
        print(`\n${c.color(c.COLORS.BOLD + c.COLORS.CYAN, "● Suite: " + name)}\n`);
        if (type(options.modules) == "array") {
            print(`${INDENT}${c.color(c.COLORS.CYAN, "Modules:")} ${join(", ", options.modules)}\n`);
        }
        if (options.filter) {
            print(`${INDENT}${c.color(c.COLORS.CYAN, "Matching:")} /${options.filter}/\n`);
        }
    }
    first_result = true;
    column_count = 0;
};

function handle_wrap() {
    if (first_result) {
        print(INDENT);
        first_result = false;
        column_count = length(INDENT);
    } else if (column_count >= MAX_COLS) {
        print(`\n${INDENT}`);
        column_count = length(INDENT);
    }
}

export function on_test_result(test, result) {
    handle_wrap();
    
    if (result.status == STATUS.SKIP) {
        print(c.color(c.COLORS.YELLOW, "○"));
    } else {
        print(result.status == STATUS.PASS ? c.color(c.COLORS.GREEN, "●") : c.color(c.COLORS.RED, "■"));
    }
    
    column_count++;
};

export function on_suite_end(stats) {
    let indent = INDENT;
    if (length(stats.failures) > 0) {
        print(`\n\n${indent}${c.color(c.COLORS.BOLD + c.COLORS.RED, "Failures:")}\n`);
        for (let f in stats.failures) {
            print(`${indent}  ${c.color(c.COLORS.RED, "✖")} ${f.name}\n${indent}      ${replace(f.error, /\n/g, "\n" + indent + "      ")}\n`);
        }
    }
    if (length(stats.errors) > 0) {
        print(`\n${indent}${c.color(c.COLORS.BOLD + c.COLORS.BRED, "Errors:")}\n`);
        for (let e in stats.errors) {
            print(`${indent}  ${c.color(c.COLORS.BRED, "‼")} ${e.name}\n${indent}      ${replace(e.error, /\n/g, "\n" + indent + "      ")}\n`);
        }
    }
    if (length(stats.skips) > 0) {
        print(`\n${indent}${c.color(c.COLORS.BOLD + c.COLORS.YELLOW, "Skipped:")}\n`);
        for (let s in stats.skips) {
            print(`${indent}  ${c.color(c.COLORS.YELLOW, "○")} ${s.name}\n`);
        }
    }

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
