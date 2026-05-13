# syntax=docker/dockerfile:1
# check=skip=InvalidDefaultArgInFrom
ARG SDK_ARCH
ARG SDK_VERSION
FROM ghcr.io/openwrt/rootfs:${SDK_ARCH}-${SDK_VERSION}

ARG PKG_DEPENDS

# Universal Package Manager Wrapper
RUN mkdir -p /var/lock && \
  if command -v apk >/dev/null; then \
    apk update && \
    apk add --no-cache $(echo $PKG_DEPENDS) libmbedtls libwolfssl libopenssl \
    rpcd uhttpd luci-ssl luci-mod-admin-full luci-light inotifywait openssl-util; \
  else \
    opkg update && \
    opkg install --force-reinstall $(echo $PKG_DEPENDS) libmbedtls libwolfssl libopenssl \
    rpcd uhttpd luci-ssl luci-mod-admin-full luci-light inotifywait openssl-util; \
  fi

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
