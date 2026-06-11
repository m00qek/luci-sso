return {
    pattern: "*_test*.uc",
    lib_paths: [
        "/usr/lib/ucode",
        "/usr/share/luci-sso/test",
    ],
    mocks: {
        uclient: null,
        uloop: null,
        ubus: null,
        http_client: { proxy: '/usr/share/luci-sso/test/proxies/http_client.uc' },
    },
};
