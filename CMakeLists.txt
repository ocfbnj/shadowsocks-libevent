cmake_minimum_required(VERSION 3.16)

project(shadowsocks-libevent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_subdirectory(test)

list(APPEND src
        socks.c
        tcp.c
        client.c
        proxy.c
        crypto.c
        aead.c
        config.c
        main.c)

set(LIBEVENT_STATIC_LINK TRUE)
find_package(Libevent REQUIRED core extra)

find_library(MBEDCRYPTO libmbedcrypto.a)
find_library(MBEDTLS libmbedtls.a)

find_library(SODIUM libsodium.a)

list(APPEND deps
        libevent::core
        libevent::extra

        ${MBEDTLS}
        ${MBEDCRYPTO}
        ${MBEDX509}

        ${SODIUM})

add_executable(shadowsocks-libevent ${src})
target_include_directories(shadowsocks-libevent PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(shadowsocks-libevent ${deps})
