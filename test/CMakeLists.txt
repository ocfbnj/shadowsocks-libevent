find_package(GTest CONFIG)

if (GTest_FOUND)
    find_library(MBEDCRYPTO libmbedcrypto.a)
    find_library(MBEDTLS libmbedtls.a)

    find_library(SODIUM libsodium.a)

    list(APPEND deps
            GTest::gtest
            GTest::gtest_main

            ${MBEDTLS}
            ${MBEDCRYPTO}

            ${SODIUM})

    add_executable(test test.cpp
            ../crypto.c ../aead.c ../crypto.c)
    target_link_libraries(test ${deps})
endif ()
