# Warning! This is an automatically generated file!
#
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(BACnet LANGUAGES C)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(SpicyPlugin REQUIRED)

# Set minimum versions that this plugin needs.
#spicy_required_version("1.2.0")
#zeek_required_version("6.0.0")

if(NOT CMAKE_BUILD_TYPE)
    # Default to the release build
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
endif(NOT CMAKE_BUILD_TYPE)

add_subdirectory(analyzer)
