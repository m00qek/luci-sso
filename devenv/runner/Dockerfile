ARG SDK_ARCH
ARG SDK_VERSION
FROM ghcr.io/openwrt/rootfs:${SDK_ARCH}-${SDK_VERSION}

ARG PKG_DEPENDS

# 1. Install LuCI, ucode, and system services
# We force-reinstall ucode/libucode to ensure dynamic symbol export is enabled.
RUN mkdir -p /var/lock && \
  opkg update && \
  opkg install --force-reinstall \
  ucode \
  libucode20230711 \
  $(echo $PKG_DEPENDS) \
  ucode-mod-math \
  ucode-mod-uloop \
  luci-light \
  luci-mod-admin-full \
  rpcd \
  uhttpd \
  luci-ssl \
  openssl-util

# 2. Set default system credentials (root:admin)
RUN printf "admin\nadmin\n" | passwd root

# 3. Create necessary system directories
RUN mkdir -p /etc/config \
  /etc/luci-sso/certs \
  /usr/libexec/rpcd \
  /var/run/ubus \
  /var/lock \
  /var/state \
  /tmp/sessions \
  /tmp/luci-modulecache

# 4. Finalize
WORKDIR /app
COPY devenv/runner/start-services.sh /usr/bin/start-services
RUN chmod +x /usr/bin/start-services

CMD ["/usr/bin/start-services"]
