ARG SDK_ARCH=x86-64
ARG SDK_VERSION=24.10.5
FROM ghcr.io/openwrt/sdk:${SDK_ARCH}-${SDK_VERSION}

# Copy SDK to /sdk because /builder is defined as a VOLUME in the base image.
# Changes made to a VOLUME during 'docker build' are discarded and not saved 
# to the image layers. Moving it to /sdk ensures our compiled headers persist.
USER root
RUN cp -a /builder /sdk && chown -R buildbot:buildbot /sdk
USER buildbot

WORKDIR /sdk

# These **MUST** run together in the same RUN clause
# Use GitHub mirrors for better reliability and speed during feed updates.
# Tracking the openwrt-24.10 branch to match the SDK version.
RUN echo "src-git base https://github.com/openwrt/openwrt.git;openwrt-24.10" > feeds.conf \
  && echo "src-git packages https://github.com/openwrt/packages.git;openwrt-24.10" >> feeds.conf \
  && ./scripts/feeds update base packages \
  && ./scripts/feeds install ucode libmbedtls \
  && echo 'CONFIG_PACKAGE_libmbedtls=y' >> .config \
  && echo "CONFIG_PACKAGE_ucode=y" >> .config \
  && make defconfig \
  && make package/mbedtls/compile -j$(nproc) \
  && make package/ucode/compile -j$(nproc) 
