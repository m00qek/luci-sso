=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**, clear **Require Verified Email**, and click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.require_email_verified='0'
    uci commit luci-sso
    ```
