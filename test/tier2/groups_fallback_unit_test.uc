import { it, assert, truthy, falsy } from 'utest';

it('ucode: truthiness of empty array', () => {
    let a = [];
    assert.match(truthy(), a, "Empty array SHOULD be truthy in ucode");
    
    let b = a || ["fallback"];
    assert.match([], b, "|| fallback SHOULD NOT trigger for empty array");
});

it('ucode: truthiness of null/undefined', () => {
    let a = null;
    assert.match(falsy(), a, "null SHOULD be falsy");
    let b = a || ["fallback"];
    assert.match(["fallback"], b, "|| fallback SHOULD trigger for null");

    let c = {}.missing;
    assert.match(falsy(), c, "undefined SHOULD be falsy");
    let d = c || ["fallback"];
    assert.match(["fallback"], d, "|| fallback SHOULD trigger for undefined");
});
