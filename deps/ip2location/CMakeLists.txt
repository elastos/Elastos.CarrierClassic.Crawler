project(IP2Location8)

include(CarrierDefaults)
include(ExternalProject)

if(WIN32)
    message(FATAL_ERROR "TODO: not support windows build")
else()
    include(ExternalConfigureArgs)

    set(CONFIGURE_CMD
        touch README &&
        aclocal &&
        automake --gnu --add-missing &&
        autoconf &&
        autoreconf -fi &&
        ./configure)

    set(CONFIGURE_ARGS
        "--prefix=${CARRIER_INT_DIST_DIR}"
        "--enable-shared=no"
        "--disable-shared"
        "--enable-static=yes"
        ${CONFIGURE_ARGS_INIT})

    set(BUILD_CMD "make")

    set(INSTALL_CMD "make")
    set(INSTALL_ARGS "install")
endif()

ExternalProject_Add(
    IP2Location8

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/chrislim2888/IP2Location-C-Library/archive/8.0.7.tar.gz"
    URL_HASH SHA256=79382611b735e3b31bc22a74912a29b7b08f5472fd74dc0f626cef1f1dbbe811
    DOWNLOAD_NAME "IP2Location-C-Library-8.0.7.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    BUILD_IN_SOURCE 1

    CONFIGURE_COMMAND ${CONFIGURE_CMD} ${CONFIGURE_ARGS}
    BUILD_COMMAND ${BUILD_CMD} ${BUILD_ARGS}
    INSTALL_COMMAND ${INSTALL_CMD} ${INSTALL_ARGS}
)
