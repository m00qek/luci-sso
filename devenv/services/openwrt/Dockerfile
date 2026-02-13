ARG SDK_ARCH
ARG SDK_VERSION
FROM ghcr.io/openwrt/rootfs:${SDK_ARCH}-${SDK_VERSION}

ARG PKG_DEPENDS
RUN mkdir -p /var/lock && \
  opkg update && \
  opkg install --force-reinstall $(echo $PKG_DEPENDS)

# DEV dependencies
RUN opkg install --force-reinstall \
  rpcd uhttpd luci-ssl luci-mod-admin-full luci-light inotifywait openssl-util

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
