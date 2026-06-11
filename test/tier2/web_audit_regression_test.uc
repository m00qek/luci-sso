import { it, assert, truthy } from 'utest';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

function make_web_deps(io) {
	return {
		getenv: (k)    => io.getenv(k),
		stdout: io.stdout,
		log:    (l, m) => io.log(l, m)
	};
}

it('web: audit reproduction - missing status codes 429 and 503', () => {
    let factory = mock.create();

    // 1. Check 429
    let out_429 = factory.get_stdout((io) => {
        web.render_error(make_web_deps(io), "TOO_MANY_REQUESTS", 429);
    });
    // Expected: 429 Too Many Requests, Actual: fallback to 500
    assert.match(truthy(), index(out_429, "Status: 429 Too Many Requests") != -1, "Status 429 should map to correct message, got: " + out_429);

    // 2. Check 503
    let out_503 = factory.get_stdout((io) => {
        web.render_error(make_web_deps(io), "SSO_DISABLED", 503);
    });
    // Expected: 503 Service Unavailable, Actual: fallback to 500
    assert.match(truthy(), index(out_503, "Status: 503 Service Unavailable") != -1, "Status 503 should map to correct message, got: " + out_503);
});

it('web: audit reproduction - missing error codes in ERROR_MAP', () => {
    let factory = mock.create();

    // 1. Check TOO_MANY_REQUESTS
    let out_tmr = factory.get_stdout((io) => {
        web.render_error(make_web_deps(io), "TOO_MANY_REQUESTS", 429);
    });
    assert.match(truthy(), index(out_tmr, "Error: Too many requests. Please wait before trying again.") != -1, "TOO_MANY_REQUESTS error message should be present");

    // 2. Check SSO_DISABLED
    let out_sd = factory.get_stdout((io) => {
        web.render_error(make_web_deps(io), "SSO_DISABLED", 503);
    });
    assert.match(truthy(), index(out_sd, "Error: Single Sign-On is not enabled on this device.") != -1, "SSO_DISABLED error message should be present");

    // 3. Check 'NOT_FOUND'
    let out_nf = factory.get_stdout((io) => {
        web.render_error(make_web_deps(io), "NOT_FOUND", 404);
    });
    assert.match(truthy(), index(out_nf, "Error: The requested path was not found.") != -1, "NOT_FOUND error message should be present");
});
