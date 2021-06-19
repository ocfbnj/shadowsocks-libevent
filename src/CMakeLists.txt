add_executable(
    ${CMAKE_PROJECT_NAME}
    aead.c
    cipher.c
    context.c
    server.c
    client.c
    proxy.c
    socks.c
    config.c
    tcp.c
    main.c)

target_link_libraries(shadowsocks-libevent CONAN_PKG::libevent CONAN_PKG::libsodium CONAN_PKG::mbedtls)
