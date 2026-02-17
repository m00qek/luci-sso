import { test, assert, assert_eq } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

test('web: render - handle both string and integer status codes safely', () => {
    let factory = mock.create();

    // Test with integer status
    let out_int = factory.get_stdout((io) => {
        web.render(io, { status: 404, headers: {}, body: "" });
    });
    assert(index(out_int, "Status: 404 Not Found") != -1, "Integer status should map to correct message");

    // Test with string status
    let out_str = factory.get_stdout((io) => {
        web.render(io, { status: "404", headers: {}, body: "" });
    });
    assert(index(out_str, "Status: 404 Not Found") != -1, "String status should map to correct message");
});
