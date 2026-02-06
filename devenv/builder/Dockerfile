ARG SDK_ARCH
ARG SDK_VERSION
FROM ghcr.io/openwrt/sdk:${SDK_ARCH}-${SDK_VERSION}

# Copy SDK to /sdk because /builder is defined as a VOLUME in the base image.
USER root
RUN cp -a /builder /sdk && chown -R buildbot:buildbot /sdk
USER buildbot

WORKDIR /sdk

# Layer 1: Setup Feeds (Slowest, Network dependent)
RUN echo "src-git base https://github.com/openwrt/openwrt.git;openwrt-24.10" > feeds.conf \
  && echo "src-git packages https://github.com/openwrt/packages.git;openwrt-24.10" >> feeds.conf \
  && ./scripts/feeds update base packages

# Layer 2: Install Packages into SDK (Metadata only)
RUN ./scripts/feeds install ucode libmbedtls libwolfssl

# Layer 3: Warming up dependencies (CPU intensive)
RUN echo 'CONFIG_PACKAGE_libmbedtls=y' >> .config \
  && echo 'CONFIG_PACKAGE_libwolfssl=y' >> .config \
  && echo "CONFIG_PACKAGE_ucode=y" >> .config \
  && make defconfig \
  && make package/mbedtls/compile -j$(nproc) \
  && make package/wolfssl/compile -j$(nproc) \
  && make package/ucode/compile -j$(nproc)

# Pre-create the package directory
RUN mkdir -p /sdk/package/luci-sso
