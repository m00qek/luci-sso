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

# Test runner: ucode-utest from the packages.ucode.dev feed.
#
# Replaces the former bind-mount of a sibling ../../utest working tree, which
# made the effective runner version whatever happened to be checked out next
# door and left CI with no runner at all. The feed directory is the OpenWrt
# minor series (24.10, 25.12), derived from SDK_VERSION.
ARG SDK_VERSION
ARG UTEST_FEED=https://m00qek.github.io/packages.ucode.dev
# Pinned, not "whatever is latest": the install layer is cached on the Dockerfile
# text, so without a version here a rebuild silently keeps the utest that was
# current when the layer was first built. Bumping UTEST_VERSION invalidates the
# layer, and the assertion below fails the build if the feed served something else.
ARG UTEST_VERSION=1.5.1
RUN FEED_DIR="$(echo "$SDK_VERSION" | cut -d. -f1,2)" && \
  if command -v apk >/dev/null; then \
    mkdir -p /etc/apk/keys /etc/apk/repositories.d && \
    wget -qO /etc/apk/keys/packages.ucode.dev.pem "$UTEST_FEED/$FEED_DIR/feed.pub.pem" && \
    echo "$UTEST_FEED/$FEED_DIR" >> /etc/apk/repositories.d/customfeeds.list && \
    apk update && \
    apk add --no-cache ucode-utest; \
  else \
    mkdir -p /etc/opkg/keys && \
    wget -qO /etc/opkg/keys/a2288d4745630a38 "$UTEST_FEED/$FEED_DIR/feed.pub" && \
    echo "src/gz ucode.dev $UTEST_FEED/$FEED_DIR" >> /etc/opkg/customfeeds.conf && \
    opkg update && \
    opkg install ucode-utest; \
  fi && \
  test -x /usr/bin/utest && test -f /usr/share/ucode/utest.uc && test -d /usr/share/ucode/utest && \
  got="$(if command -v apk >/dev/null; then apk list -I 2>/dev/null | grep -o 'ucode-utest-[0-9][^ ]*'; \
         else opkg list-installed 2>/dev/null | grep '^ucode-utest'; fi)" && \
  case "$got" in *"$UTEST_VERSION"*) echo "utest OK: $got" ;; \
    *) echo "ERROR: expected utest $UTEST_VERSION, feed served: $got" >&2; exit 1 ;; esac

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
