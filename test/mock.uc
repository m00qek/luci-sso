'use strict';

import * as lucihttp from 'lucihttp';

/**
 * Creates a Query Handle for inspecting captured history.
 * Matches by type and positional arguments.
 * @private
 */
function create_query_handle(history) {
	return {
		called: function(type, arg1, arg2, arg3) {
			for (let entry in history) {
				if (entry.type !== type) continue;
				
				// Generic positional argument matching
				if (arg1 != null && entry.args[0] !== arg1) continue;
				if (arg2 != null && entry.args[1] !== arg2) continue;
				if (arg3 != null && entry.args[2] !== arg3) continue;
				
				return true;
			}
			return false;
		},
		all: function() { return history; }
	};
};

/**
 * Builds the Dumb I/O provider handle.
 * @private
 */
function build_provider(state) {
	const trackable = (name, fn) => (...args) => {
		if (state.recording) push(state.history, { type: name, args: args });
		return fn(...args);
	};

	let io = {
		// Private state handle for inheritance
		__state__: state,

		time: trackable("time", () => state.now),
		
		read_file: trackable("read_file", (path) => state.files[path]),
		
		write_file: trackable("write_file", (path, data) => {
			if (state.read_only) {
				state.last_error = "Read-only file system";
				return false;
			}
			state.files[path] = data;
			return true;
		}),
		
		rename: trackable("rename", (old, newpath) => {
			if (state.read_only) {
				state.last_error = "Permission denied";
				return false;
			}
			state.files[newpath] = state.files[old];
			delete state.files[old];
			return true;
		}),
		
		remove: trackable("remove", (path) => {
			if (state.read_only) {
				state.last_error = "Permission denied";
				return false;
			}
			delete state.files[path];
			return true;
		}),
		
		mkdir: trackable("mkdir", (path, mode) => {
			if (state.read_only) {
				state.last_error = "Permission denied";
				return false;
			}
			// Simulate POSIX: return false if already exists
			if (state.files[path] != null) return false;
			
			// Track directory as a special entry
			state.files[path] = { ".type": "directory" };
			return true;
		}),
		
		chmod: trackable("chmod", (path, mode) => {
			if (state.read_only) {
				state.last_error = "Permission denied";
				return false;
			}
			return true;
		}),
		
		lsdir: trackable("lsdir", (path) => {
			let results = [];
			let prefix = path;
			if (substr(prefix, -1) != "/") prefix += "/";
			for (let f in state.files) {
				if (index(f, prefix) == 0) push(results, substr(f, length(prefix)));
			}
			return results;
		}),
		
		stat: trackable("stat", (path) => (state.files[path] != null ? { mtime: state.now } : null)),
		
		getenv: trackable("getenv", (key) => state.env[key]),
		
		urlencode: (s) => lucihttp.urlencode(s), // Pure function, no tracking needed
		
		log: trackable("log", (level, msg) => {
			// In mock mode, we just record it. History is handled by the trackable wrapper.
		}),
		
		http_get: trackable("http_get", (url) => {
			// MANDATORY HTTPS: (Mirroring Production Blocker #6)
			if (substr(url, 0, 8) !== "https://") return { error: "HTTPS_REQUIRED" };
			let res = state.responses[url];
			if (!res) return { status: 404, body: { read: () => "" } };
			if (res.error) return { error: res.error };

			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		}),
		
		http_post: trackable("http_post", (url, opts) => {
			// MANDATORY HTTPS: (Mirroring Production Blocker #6)
			if (substr(url, 0, 8) !== "https://") return { error: "HTTPS_REQUIRED" };
			let res = state.responses[url];
			if (!res) return { status: 404, body: { read: () => "" } };
			if (res.error) return { error: res.error };

			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		}),
		
		ubus_call: trackable("ubus", (obj, method, args) => {
			let key = `${obj}:${method}`;
			let res = state.ubus[key] || state.ubus[obj] || {};
			return (type(res) == "function") ? res(args) : res;
		}),
		
		uci_cursor: () => {
			return {
				get_all: function(pkg, sec) {
					let p = state.uci[pkg];
					if (type(p) == "object") return p[sec];
					return null;
				},
				foreach: function(pkg, type_name, cb) {
					let p = state.uci[pkg];
					if (type(p) != "object") return;
					for (let section_name in p) {
						let section = p[section_name];
						if (section[".type"] === type_name) cb(section);
					}
				}
			};
		},
		
		fserror: () => state.last_error || "No error",
		
		stdout: {
			write: (s) => { 
				state.stdout_buf += s;
				if (state.recording) push(state.history, { type: "stdout", args: [s] });
			},
			flush: () => {}
		}
	};
	return io;
};

/**
 * Builds the Fluent Factory DSL.
 * @private
 */
function build_factory(state) {
	const scoped = (key) => (data, cb) => {
		let next_state = { ...state, [key]: { ...state[key], ...data } };
		if (cb) return cb(build_provider(next_state));
		return build_factory(next_state);
	};

	const intercepted = (init, extractor) => (cb) => {
		let next_state = { ...state, ...init };
		cb(build_provider(next_state));
		return extractor(next_state);
	};

	return {
		using: (io) => build_factory({ ...io.__state__ }),

		with_files: scoped("files"),
		with_uci: scoped("uci"),
		with_env: scoped("env"),
		with_ubus: scoped("ubus"),
		with_responses: scoped("responses"),

		with_read_only: (cb) => {
			let next_state = { ...state, read_only: true };
			if (cb) return cb(build_provider(next_state));
			return build_factory(next_state);
		},

		spy: (cb) => {
			let next_state = { ...state, recording: true, history: [ ...state.history ] };
			let io = build_provider(next_state);
			cb(io);
			return create_query_handle(next_state.history);
		},

		get_stdout: (cb) => {
			let next_state = { ...state, stdout_buf: "" };
			let io = build_provider(next_state);
			cb(io);
			return next_state.stdout_buf;
		}
	};
};

/**
 * Initial Factory Entry Point.
 */
export function create() {
	return build_factory({
		now: 1516239022,
		files: {},
		env: {},
		uci: {},
		ubus: {},
		responses: {},
		recording: false,
		history: [],
		stdout_buf: "",
		read_only: false,
		last_error: null
	});
};