project(libcrystal)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    libcrystal

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/iwhisperio/libcrystal/archive/release-v1.0.4.tar.gz"
    URL_HASH SHA256=1d2bb1a6f003dc2fb2314b3329904db522dee9ede6d287bd13460d0814ab656c
    DOWNLOAD_NAME "release-v1.0.4.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DENABLE_STATIC=TRUE
        -DENABLE_SHARED=FALSE
        -DLIBSODIUM_STATIC=TRUE
        -DENABLE_CRYPTO=TRUE
        -DENABLE_TESTS=FALSE
        ${CMAKE_ARGS_INIT}
)
