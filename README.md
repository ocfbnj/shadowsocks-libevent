# shadowsocks-libevent

An unofficial shadowsocks implementation that can work with official shadowsocks.

This project is for learning purposes.

## Requires

- [libevent](https://github.com/libevent/libevent) for asynchronous I/O and event loop.
- [libsodium](https://github.com/jedisct1/libsodium) for AEAD_CHACHA20_POLY1305 cipher and helpers.
- [mbedtls](https://github.com/ARMmbed/mbedtls) for key derivation.

## Test on

- [Ubuntu Server 20.04.1 LTS](https://releases.ubuntu.com/20.04.1/ubuntu-20.04.1-live-server-amd64.iso)
- [libevent 2.12.2-stable](https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz)
- [libsodium 1.0.18-stable](https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz)
- [mbedtls 2.25.0](https://github.com/ARMmbed/mbedtls/archive/v2.25.0.tar.gz)
