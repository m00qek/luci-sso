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

it('web: render - handle both string and integer status codes safely', () => {
    let factory = mock.create();

    // Test with integer status
    let out_int = factory.get_stdout((io) => {
        web.render(make_web_deps(io), { status: 404, headers: {}, body: "" });
    });
    assert.match(truthy(), index(out_int, "Status: 404 Not Found") != -1, "Integer status should map to correct message");

    // Test with string status
    let out_str = factory.get_stdout((io) => {
        web.render(make_web_deps(io), { status: "404", headers: {}, body: "" });
    });
    assert.match(truthy(), index(out_str, "Status: 404 Not Found") != -1, "String status should map to correct message");
});
