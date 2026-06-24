import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import * as common from 'luci_sso.session.common';
import { CRYPTO_INIT_FAILED } from 'luci_sso.errors';

/**
 * System secret key management (locking, generation, persistence).
 */

/**
 * Internal helper to get/generate the router secret key.
 * Uses atomic rename and re-read pattern to prevent race conditions.
 * @param {object} deps - { fs, clock, log }
 * @returns {object} - Result Object {ok, data: key/error}
 */
export function get(deps) {
	let key = null;
	try {
		key = deps.fs.readfile(common.SECRET_KEY_PATH);
	} catch (e) {
		// File missing or unreadable
	}

	if (!key || length(key) === 0) {
		// 1. Atomic Lock Attempt: Try to create a lock directory
		const lock_path = common.SECRET_KEY_PATH + ".lock";
		let acquired = false;
		try {
			// Ensure parent directory exists (Avoid SYSTEM_INIT_FAILED on fresh boot)
			deps.fs.mkdir("/etc/luci-sso", 0700);
			acquired = deps.fs.mkdir(lock_path, 0700);
		} catch (e) {
			// Lock already held by another process
		}

		if (!acquired) {
			// W2: Self-healing for stale locks (Audit Warning #104)
			// If a process crashed during generation, the lock persists.
			// 30s is more than enough for a 32-byte CSPRNG write + rename.
			let st = deps.fs.stat(lock_path);
			if (st && st.mtime !== null && (deps.clock.time() - st.mtime) > 30) {
				deps.log("warn", "Stale secret key lock detected; performing self-healing cleanup");
				try { deps.fs.unlink(lock_path); } catch (e) {}
				try { acquired = deps.fs.mkdir(lock_path, 0700); } catch (e) {}
			}
		}

		if (acquired) {
			try {
				// 2. We are the generator: Generate and Write
				let res = crypto.random(32);
				if (!res.ok) {
					deps.log("error", "CRITICAL: CSPRNG failure during secret key generation");
					try { deps.fs.unlink(lock_path); } catch (e) {}
					return Result.err(CRYPTO_INIT_FAILED);
				}

				let new_key = res.data;
				let tmp_path = common.SECRET_KEY_PATH + ".tmp";
				// MANDATORY: Restricted permissions for secrets
				if (!deps.fs.writefile(tmp_path, new_key)) {
					deps.log("error", "CRITICAL: Failed to write secret key");
					try { deps.fs.unlink(lock_path); } catch (e) {}
					return Result.err("SYSTEM_KEY_WRITE_FAILED");
				}
				deps.fs.chmod(tmp_path, 0600);
				if (!deps.fs.rename(tmp_path, common.SECRET_KEY_PATH)) {
					deps.log("error", "CRITICAL: Failed to atomically install secret key");
					try { deps.fs.unlink(tmp_path); } catch (e) {}
					try { deps.fs.unlink(lock_path); } catch (e) {}
					return Result.err("SYSTEM_KEY_WRITE_FAILED");
				}
				key = new_key;
			} catch (e) {
				deps.log("error", `Failed to generate or write secret key: ${e}`);
				try { deps.fs.unlink(lock_path); } catch (ex) {}
				return Result.err("SYSTEM_KEY_WRITE_FAILED");
			}
			// 3. ALWAYS release the lock
			try { deps.fs.unlink(lock_path); } catch (e) {}
		} else {
			// 4. BLOCKER FIX: Retry with backoff if lock is held (B2)
			let retries = 0;
			const max_retries = 5;

			while (retries < max_retries) {
				// Wait for a clock tick (at least 1 second in production)
				deps.clock.sleep(1);

				try {
					key = deps.fs.readfile(common.SECRET_KEY_PATH);
				} catch (e) {
					// File still missing or unreadable
				}

				if (key && length(key) > 0) break;
				retries++;
			}

			if (!key || length(key) === 0) {
				// FAIL: Do not fallback to random key (avoids transient session invalidation)
				return Result.err("SYSTEM_KEY_UNAVAILABLE");
			}
		}
	}

	if (!key || length(key) === 0) {
		return Result.err("SYSTEM_KEY_GENERATION_FAILED");
	}

	return Result.ok(key);
};
