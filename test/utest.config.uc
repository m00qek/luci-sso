return {
    pattern: "*_test*.uc",
    lib_paths: [
        "/usr/lib/ucode",
        ".",
        "unit",
        "../src",
    ],
    mocks: {
        fs:          null,
        uci:         null,
        ubus:        null,
        uclient:     null,
        uloop:       null,
        http_client: { proxy: 'proxies/http_client.uc' },
        clock:       { proxy: 'proxies/clock.uc' },
        native:      { proxy: 'proxies/native.uc' },
    },
};
