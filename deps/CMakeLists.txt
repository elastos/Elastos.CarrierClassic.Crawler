include(AddSubModule)

add_submodule(platform-specific)

add_submodule(libconfig)

add_submodule(libsodium
    DEPENDS platform-specific)

if(WIN32)
#    add_submodule(slim-pthread
    add_submodule(pthreads-w32
        DEPENDS platform-specific)
endif()

add_submodule(libcrystal
    DEPENDS platform-specific libsodium)

add_submodule(toxcore0
    DIRECTORY toxcore
    DEPENDS platform-specific libsodium libconfig)

add_submodule(IP2Location8
    DIRECTORY ip2location
    DEPENDS platform-specific)
