return {
    pattern: "*_test*.uc",
    lib_paths: [
        "/usr/lib/ucode",
        "/usr/share/luci-sso/test",
    ],
    mocks: {
        fs:          null,
        uci:         null,
        ubus:        null,
        http_client: { proxy: '/usr/share/luci-sso/test/proxies/http_client.uc' },
        clock:       { proxy: '/usr/share/luci-sso/test/proxies/clock.uc' },
    },
};
