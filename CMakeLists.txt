cmake_minimum_required(VERSION 3.5)
cmake_policy(VERSION 3.5)
project(elastos-carrier-crawler)

# set(CMAKE_VERBOSE_MAKEFILE TRUE)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(CarrierDefaults)
include(AddSubModule)

add_subdirectory(deps)
add_subdirectory(src)