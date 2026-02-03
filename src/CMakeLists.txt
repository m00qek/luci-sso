cmake_minimum_required(VERSION 3.10)
project(ucode_native_modules C)

find_library(UCODE_LIB ucode)
find_library(MBEDTLS_LIB mbedtls)
find_library(MBEDX509_LIB mbedx509)
find_library(MBEDCRYPTO_LIB mbedcrypto)

# Automatically find all .c files in this directory
file(GLOB SOURCES CONFIGURE_DEPENDS "*.c")
message(STATUS "Found sources: ${SOURCES}")

foreach(SRC ${SOURCES})
    get_filename_component(LIBNAME ${SRC} NAME_WE)
    
    # Create a shared library for each .c file
    add_library(${LIBNAME} SHARED ${SRC})
    
    # Remove the "lib" prefix
    set_target_properties(${LIBNAME} PROPERTIES PREFIX "")
    
    target_link_libraries(${LIBNAME} 
        ${UCODE_LIB}
        ${MBEDTLS_LIB}
        ${MBEDX509_LIB}
        ${MBEDCRYPTO_LIB}
    )
    
    install(TARGETS ${LIBNAME} DESTINATION lib/ucode)
endforeach()