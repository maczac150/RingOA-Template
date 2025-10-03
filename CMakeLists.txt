cmake_minimum_required(VERSION 3.18)
cmake_policy(SET CMP0167 OLD)

project(SampleProject VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =========================
# Output / Compiler Settings
# =========================
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")

# =========================
# Dependencies
# =========================
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/thirdparty)
find_package(RingOA CONFIG REQUIRED HINTS ${THIRD_PARTY_DIR}/unix)

# =========================
# Build type
# =========================
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()
if(NOT CMAKE_BUILD_TYPE MATCHES "Debug|Release|RelWithDebInfo")
  message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}. Use Debug, Release, or RelWithDebInfo.")
endif()

# =========================
# Notes about LOG/SEED
# =========================
# Do NOT define LOG_LEVEL / USE_FIXED_RANDOM_SEED here.
# Inherit RingOA's PUBLIC definitions. If you MUST override:
#   - Prefer passing at configure time:  cmake -DLOG_LEVEL=3 -DUSE_FIXED_RANDOM_SEED=0 ...
#   - Or (not recommended) redefine on your target with target_compile_definitions().


# =========================
# Info
# =========================
message(STATUS "--------------------------------------------")
message(STATUS " Project Configuration Info:")
message(STATUS "--------------------------------------------")
message(STATUS "[Project Information]")
message(STATUS "  Project Name              : ${PROJECT_NAME}")
message(STATUS "  Version                   : ${PROJECT_VERSION}")
message(STATUS "  CMake Version             : ${CMAKE_VERSION}")
message(STATUS "[Build Settings]")
message(STATUS "  Build Type                : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix            : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "[Directories]")
message(STATUS "  Source Directory          : ${CMAKE_SOURCE_DIR}")
message(STATUS "  Binary Directory          : ${CMAKE_CURRENT_BINARY_DIR}")
message(STATUS "[Libraries]")
message(STATUS "  cryptoTools Directory     : ${cryptoTools_DIR}")
message(STATUS "  RingOA Directory          : ${RingOA_DIR}")

# =========================
# Subdirectories
# =========================
add_subdirectory(example)
