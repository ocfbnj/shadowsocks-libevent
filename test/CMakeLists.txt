find_package(GTest CONFIG)

if (GTest_FOUND)
    set(LIBEVENT_STATIC_LINK TRUE)
    find_package(Libevent REQUIRED core extra)

    find_library(MBEDCRYPTO libmbedcrypto.a)
    find_library(MBEDTLS libmbedtls.a)

    find_library(SODIUM libsodium.a)

    list(APPEND deps
            libevent::core
            libevent::extra
            
            GTest::gtest
            GTest::gtest_main

            ${MBEDTLS}
            ${MBEDCRYPTO}

            ${SODIUM})

    add_executable(test test.cpp
            ../cipher.c ../aead.c)
    target_link_libraries(test ${deps})
endif ()
