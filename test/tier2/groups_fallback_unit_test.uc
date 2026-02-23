import { test, assert, assert_eq } from 'testing';

test('ucode: truthiness of empty array', () => {
    let a = [];
    assert(a, "Empty array SHOULD be truthy in ucode");
    
    let b = a || ["fallback"];
    assert_eq(b, [], "|| fallback SHOULD NOT trigger for empty array");
});

test('ucode: truthiness of null/undefined', () => {
    let a = null;
    assert(!a, "null SHOULD be falsy");
    let b = a || ["fallback"];
    assert_eq(b, ["fallback"], "|| fallback SHOULD trigger for null");

    let c = {}.missing;
    assert(!c, "undefined SHOULD be falsy");
    let d = c || ["fallback"];
    assert_eq(d, ["fallback"], "|| fallback SHOULD trigger for undefined");
});
