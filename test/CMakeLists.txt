if(TARGET CONAN_PKG::gtest)
    add_executable(test test.cpp ../src/cipher.c ../src/aead.c)
    target_link_libraries(test CONAN_PKG::gtest CONAN_PKG::libevent CONAN_PKG::libsodium CONAN_PKG::mbedtls)
endif()
