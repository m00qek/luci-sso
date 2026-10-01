import { describe, it, assert } from 'utest';
import * as fs from 'fs';

// System bucket: the cleanup cron job, added by the setup script
// (files/etc/uci-defaults/10-luci-sso-setup) and removed by the package's
// pre-removal script, both through `luci-sso-cleanup --install-cron` and
// `--remove-cron`. They run for real, with the container's busybox, against
// the container's /etc/crontabs/root, which each test saves and restores.

const CRONTAB = "/etc/crontabs/root";
const SETUP = "/usr/share/luci-sso/uci-defaults/10-luci-sso-setup";
const CLEANUP = "/usr/sbin/luci-sso-cleanup";
const JOB = "0 4 * * * /usr/sbin/luci-sso-cleanup";

// Runs fn with CRONTAB holding `content` (null: no file), then puts the
// container's own crontab back, whatever happened.
function with_crontab(content, fn) {
	let saved = fs.readfile(CRONTAB);
	let failure = null;
	try {
		fs.mkdir("/etc/crontabs");
		if (content == null)
			fs.unlink(CRONTAB);
		else
			fs.writefile(CRONTAB, content);
		fn();
	} catch (e) {
		failure = e;
	}
	if (saved == null)
		fs.unlink(CRONTAB);
	else
		fs.writefile(CRONTAB, saved);
	if (failure != null) die(failure);
}

function run(cmd) {
	return system(`${cmd} >/dev/null 2>&1`);
}

function crontab() {
	return fs.readfile(CRONTAB);
}

function count(text, line) {
	return length(filter(split(text, "\n"), (l) => l == line));
}

describe('system: cron job — setup script', () => {
	it('adds the job to an empty crontab, and to a missing one', () => {
		with_crontab("", () => {
			assert.match(0, run(`sh ${SETUP}`));
			assert.match(`${JOB}\n`, crontab());
		});
		with_crontab(null, () => {
			assert.match(0, run(`sh ${SETUP}`));
			assert.match(`${JOB}\n`, crontab());
		});
	});

	it('adds the job when only a comment names the script', () => {
		let before = "# 0 4 * * * /usr/sbin/luci-sso-cleanup was dropped here\n" +
			"   # indented note about /usr/sbin/luci-sso-cleanup\n" +
			"5 * * * * /usr/bin/other-job\n";
		with_crontab(before, () => {
			assert.match(0, run(`sh ${SETUP}`));
			assert.match(before + `${JOB}\n`, crontab(), "comments and other jobs kept, the job added");
		});
	});

	it('adds nothing when an active line already runs the script, on any schedule', () => {
		for (let line in [ JOB, "30 3 * * * /usr/sbin/luci-sso-cleanup >/dev/null 2>&1", "\t@daily luci-sso-cleanup" ]) {
			with_crontab(`${line}\n`, () => {
				assert.match(0, run(`sh ${SETUP}`));
				assert.match(`${line}\n`, crontab(), line);
			});
		}
	});

	it('is idempotent: a second run adds no second job', () => {
		with_crontab("# /usr/sbin/luci-sso-cleanup\n", () => {
			run(`sh ${SETUP}`);
			run(`sh ${SETUP}`);
			assert.match(1, count(crontab(), JOB));
		});
	});

	it('puts the job on its own line when the crontab does not end with a newline', () => {
		with_crontab("# a note without a newline", () => {
			run(`sh ${SETUP}`);
			assert.match(`# a note without a newline\n${JOB}\n`, crontab());
		});
	});

	it('does not take a different script whose name only starts the same for the job', () => {
		with_crontab("0 5 * * * /usr/sbin/luci-sso-cleanup-old\n", () => {
			run(`sh ${SETUP}`);
			assert.match(1, count(crontab(), JOB));
		});
	});
});

describe('system: cron job — removal', () => {
	it('removes only the active job lines and keeps comments that name the script', () => {
		let comment = "# 0 4 * * * /usr/sbin/luci-sso-cleanup (kept)\n";
		let other = "5 * * * * /usr/bin/other-job\n";
		with_crontab(comment + `${JOB}\n` + other + "  30 3 * * * /usr/sbin/luci-sso-cleanup >/dev/null\n", () => {
			assert.match(0, run(`${CLEANUP} --remove-cron`));
			assert.match(comment + other, crontab());
		});
	});

	it('leaves a crontab without the job, or no crontab, as it is', () => {
		with_crontab("# /usr/sbin/luci-sso-cleanup\n", () => {
			assert.match(0, run(`${CLEANUP} --remove-cron`));
			assert.match("# /usr/sbin/luci-sso-cleanup\n", crontab());
		});
		with_crontab(null, () => {
			assert.match(0, run(`${CLEANUP} --remove-cron`));
			assert.match(null, crontab());
		});
	});

	it('removes exactly what the setup script added', () => {
		let before = "# /usr/sbin/luci-sso-cleanup\n5 * * * * /usr/bin/other-job\n";
		with_crontab(before, () => {
			run(`sh ${SETUP}`);
			run(`${CLEANUP} --remove-cron`);
			assert.match(before, crontab());
		});
	});
});

describe('system: luci-sso-cleanup — usage', () => {
	it('refuses an unknown option with status 2', () => {
		assert.match(2, run(`${CLEANUP} --bogus`));
	});
});
