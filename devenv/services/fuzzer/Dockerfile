FROM alpine:3.21

# Install clang 19, compiler-rt (contains libFuzzer), and crypto headers
RUN apk add --no-cache \
    bash \
    build-base \
    clang19 \
    compiler-rt \
    cmake \
    mbedtls-dev \
    wolfssl-dev \
    openssl-dev

# Set clang-19 as the default compiler
ENV CC=clang-19
ENV CXX=clang++-19

# Sanitizer test runner (`make sanitizer-test`): ucode and utest built from
# source with AddressSanitizer + UndefinedBehaviorSanitizer, so the native
# module can be loaded into a fully instrumented interpreter. Alpine's own
# ucode package is from 2022; OpenWrt's is glibc-free but built with gcc,
# whose ASan runtime does not support musl. Both pins match the devenv:
# ucode as shipped by OpenWrt (2025.07.18~3f64c808) and utest 1.5.1.
# Only the modules the native and crypto buckets load are enabled.
ARG UCODE_COMMIT=3f64c8089bf3ea4847c96b91df09fbfcaec19e1d
ARG UTEST_COMMIT=23e05f93d8bbc486a35285b7abe1c63ac3a9f7ee
ENV SANITIZE_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
RUN apk add --no-cache git json-c-dev libubox-dev && \
    git clone -q https://github.com/jow-/ucode.git /tmp/ucode && \
    git -C /tmp/ucode checkout -q "$UCODE_COMMIT" && \
    cmake -S /tmp/ucode -B /tmp/ucode/build \
        -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="$SANITIZE_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
        -DFS_SUPPORT=ON -DMATH_SUPPORT=ON -DULOOP_SUPPORT=ON \
        -DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DRTNL_SUPPORT=OFF -DNL80211_SUPPORT=OFF \
        -DRESOLV_SUPPORT=OFF -DSTRUCT_SUPPORT=OFF -DSOCKET_SUPPORT=OFF -DLOG_SUPPORT=OFF \
        -DDIGEST_SUPPORT=OFF -DZLIB_SUPPORT=OFF -DDEBUG_SUPPORT=OFF && \
    cmake --build /tmp/ucode/build -j"$(nproc)" && \
    cmake --install /tmp/ucode/build && \
    git clone -q https://github.com/m00qek/utest.git /tmp/utest && \
    git -C /tmp/utest checkout -q "$UTEST_COMMIT" && \
    mkdir -p /usr/share/ucode && \
    install -m 0755 /tmp/utest/src/utest.sh /usr/bin/utest && \
    cp /tmp/utest/src/utest.uc /usr/share/ucode/ && \
    cp -r /tmp/utest/src/utest /usr/share/ucode/ && \
    rm -rf /tmp/ucode /tmp/utest && \
    ucode -e 'import * as fs from "fs"; import * as uloop from "uloop";'

# ASan/LSan Suppressions
COPY asan.supp /etc/asan.supp
ENV LSAN_OPTIONS="suppressions=/etc/asan.supp"
ENV ASAN_OPTIONS="detect_leaks=1"

WORKDIR /work
