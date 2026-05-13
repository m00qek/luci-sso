# How to Install luci-sso

This guide describes how to install the `luci-sso` package and its required dependencies on your OpenWrt router.

---

## Step 1: Upload the Package
Upload the compiled `.ipk` file to your router (e.g., via `scp`):

```bash
scp -O bin/lib/<ARCH>/packages/luci-sso*.ipk root@192.168.1.1:/tmp/
```

## Step 2: Install Dependencies
`luci-sso` relies on several `ucode` modules and libraries. Run the following commands on the router:

```bash
opkg update
opkg install \
    ucode \
    libucode \
    ucode-mod-fs \
    ucode-mod-ubus \
    ucode-mod-uci \
    ucode-mod-math \
    ucode-mod-uclient \
    ucode-mod-uloop \
    ucode-mod-log \
    liblucihttp-ucode
```

## Step 3: Install LuCI SSO
Install the package you uploaded in Step 1:

```bash
opkg install /tmp/luci-sso*.ipk
```

---

## 🏁 Next Steps
Once installed, you need to [Configure the Service](../../reference/uci-config.md).
