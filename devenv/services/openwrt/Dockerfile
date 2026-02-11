ARG SDK_ARCH=x86-64
ARG SDK_VERSION=24.10.5
FROM ghcr.io/openwrt/rootfs:${SDK_ARCH}-${SDK_VERSION}

ARG PKG_DEPENDS
RUN mkdir -p /var/lock && \
  opkg update && \
  opkg install --force-reinstall $(echo $PKG_DEPENDS)

# DEV dependencies
RUN opkg install --force-reinstall \
  rpcd uhttpd luci-ssl luci-mod-admin-full luci-light inotifywait

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
