project(carrier-crawler C)
cmake_policy(SET CMP0054 NEW)

include(CarrierDefaults)
include(CheckIncludeFile)

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    add_definitions(-DHAVE_SYS_RESOURCE_H=1)
endif()


#configure_file(
#    version.h.in
#    version.h
#    "@ONLY")

set(SRC main.c config.c)

include_directories(
    .
    ${CMAKE_CURRENT_BINARY_DIR}/../deps/toxcore/external/src/toxcore0
    ${CARRIER_INT_DIST_DIR}/include)

link_directories(
    ${CARRIER_INT_DIST_DIR}/lib)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
endif()

set(LIBS
    toxcore
    toxdht
    toxcrypto
    toxfriends
    toxgroup
    toxmessenger
    toxnetwork
    toxnetcrypto
    crystal
    config)

if(WIN32)
    set(LIBS
        ${LIBS}
        pthread
        libsodium.lib)
else()
    set(LIBS
        ${LIBS}
        sodium)
endif()

add_executable(elacrawler ${SRC})
target_link_libraries(elacrawler ${LIBS} ${SYSTEM_LIBS})

install(TARGETS elacrawler
    RUNTIME DESTINATION "bin"
    ARCHIVE DESTINATION "lib"
    LIBRARY DESTINATION "lib")

install(FILES elacrawler.conf
    DESTINATION "etc/carrier"
    RENAME "crawler.conf")

