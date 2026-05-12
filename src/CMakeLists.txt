cmake_minimum_required(VERSION 3.10)
project(ucode_native_modules C)

include_directories(.)

find_library(UCODE_LIB ucode)
find_library(MBEDTLS_LIB mbedtls)
find_library(MBEDX509_LIB mbedx509)
find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(WOLFSSL_LIB wolfssl)

# 1. mbedTLS Target
if(MBEDTLS_LIB AND MBEDX509_LIB AND MBEDCRYPTO_LIB AND UCODE_LIB)
    message(STATUS "mbedTLS found, adding native_mbedtls target")
    add_library(native_mbedtls SHARED native_mbedtls.c native_common.c)
    set_target_properties(native_mbedtls PROPERTIES PREFIX "")
    target_link_libraries(native_mbedtls ${UCODE_LIB} ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB})
    install(TARGETS native_mbedtls DESTINATION lib/ucode)
endif()

# 2. wolfSSL Target
if(WOLFSSL_LIB AND UCODE_LIB)
    message(STATUS "wolfSSL found, adding native_wolfssl target")
    add_library(native_wolfssl SHARED native_wolfssl.c native_common.c)
    set_target_properties(native_wolfssl PROPERTIES PREFIX "")
    target_link_libraries(native_wolfssl ${UCODE_LIB} ${WOLFSSL_LIB})
    install(TARGETS native_wolfssl DESTINATION lib/ucode)
endif()

# 3. Fuzzing Target (Requires clang and -fsanitize=fuzzer)
option(ENABLE_FUZZING "Build fuzzer targets" OFF)
if(ENABLE_FUZZING)
    if(MBEDTLS_LIB)
        add_executable(fuzz_mbedtls ../test/fuzz_test.c native_mbedtls.c)
        target_compile_options(fuzz_mbedtls PRIVATE -fsanitize=fuzzer,address)
        target_link_libraries(fuzz_mbedtls -fsanitize=fuzzer,address ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB})
    endif()

    if(WOLFSSL_LIB)
        add_executable(fuzz_wolfssl ../test/fuzz_test.c native_wolfssl.c)
        target_compile_options(fuzz_wolfssl PRIVATE -fsanitize=fuzzer,address)
        target_link_libraries(fuzz_wolfssl -fsanitize=fuzzer,address ${WOLFSSL_LIB})
    endif()
endif()
