FROM alpine:3.21

# Install clang 19, compiler-rt (contains libFuzzer), and crypto headers
RUN apk add --no-cache \
    bash \
    build-base \
    clang19 \
    compiler-rt \
    cmake \
    mbedtls-dev \
    wolfssl-dev

# Set clang-19 as the default compiler
ENV CC=clang-19
ENV CXX=clang++-19

# ASan/LSan Suppressions
COPY asan.supp /etc/asan.supp
ENV LSAN_OPTIONS="suppressions=/etc/asan.supp"
ENV ASAN_OPTIONS="detect_leaks=1"

WORKDIR /work
