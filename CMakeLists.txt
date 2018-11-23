# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008"
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles"
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 2.4)

# project name and language
project(Detours CXX)

# check build type
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Debug")
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# make uppercase string of build type
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)

# check build type again
if (NOT uppercase_CMAKE_BUILD_TYPE MATCHES "^(DEBUG|RELEASE|RELWITHDEBINFO|MINSIZEREL)$")
    message(FATAL_ERROR "Invalid value for CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# enable C compilers
enable_language(C)

# enable Win32 resource
enable_language(RC)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # using Clang
    set(CMAKE_C_FLAGS "-static")
    set(CMAKE_CXX_FLAGS "-static")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # using GCC
    set(CMAKE_C_FLAGS "-static -static-libgcc -static-libstdc++")
    set(CMAKE_CXX_FLAGS "-static -static-libgcc -static-libstdc++")
elseif (MSVC)
    # replace "/MD" with "/MT" (building without runtime DLLs)
    set(CompilerFlags
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    foreach(CompilerFlags ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlags} "${${CompilerFlags}}")
    endforeach()
endif()

##############################################################################
# options

option(DETOURS_WIN_7 "DETOURS_WIN_7" OFF)
option(DETOURS_CL_17_OR_NEWER "DETOURS_CL_17_OR_NEWER" OFF)
option(DETOURS_ANALYZE "DETOURS_ANALYZE" OFF)

##############################################################################

# DETOURS_CONFIG
set(DETOURS_CONFIG "")

# DETOURS_TARGET_PROCESSOR
set(DETOURS_TARGET_PROCESSOR "X86")

# PROCESSOR_ARCHITECTURE
set(PROCESSOR_ARCHITECTURE "X86")

# PROCESSOR_ARCHITEW6432
set(PROCESSOR_ARCHITEW6432 "")

##############################################################################

if (DETOURS_TARGET_PROCESSOR STREQUAL "" AND NOT (PROCESSOR_ARCHITEW6432 STREQUAL ""))
    set(DETOURS_TARGET_PROCESSOR "X86")
endif()

if (DETOURS_TARGET_PROCESSOR STREQUAL "")
    set(DETOURS_TARGET_PROCESSOR "${PROCESSOR_ARCHITECTURE}")
endif()

# uppercase DETOURS_TARGET_PROCESSOR
string(TOUPPER "${DETOURS_TARGET_PROCESSOR}" DETOURS_TARGET_PROCESSOR_UPPER)
set(DETOURS_TARGET_PROCESSOR ${DETOURS_TARGET_PROCESSOR_UPPER})

if (DETOURS_TARGET_PROCESSOR STREQUAL "AMD64")
    set(DETOURS_TARGET_PROCESSOR "X64")
endif()

if (DETOURS_TARGET_PROCESSOR MATCHES "64")
    set(DETOURS_64BIT 1)
    set(DETOURS_BITS 64)
else()
    set(DETOURS_32BIT 1)
    set(DETOURS_BITS 32)
endif()

##############################################################################

if (DETOURS_TARGET_PROCESSOR STREQUAL "X64")
    message(STATUS "Building for 64-bit X64.")
    set(DETOURS_SOURCE_BROWSING 0)
    set(DETOURS_OPTION_PROCESSOR X86)
    set(DETOURS_OPTION_BITS 32)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "IA64")
    message(STATUS "Building for 64-bit IA64.")
    set(DETOURS_OPTION_PROCESSOR X86)
    set(DETOURS_OPTION_BITS 32)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "X86")
    message(STATUS "Building for 32-bit X86.")
    set(DETOURS_OPTION_BITS 64)
    # Don't set DETOURS_OPTION_PROCESSOR for x64 because we don't *know* that
    # we'll run on a 64-bit machine.
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "ARM")
    message(STATUS "Building for 32-bit ARM.")
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "ARM64")
    message(STATUS "Building for 64-bit ARM.")
else()
    message(STATUS "Note: To select the target processor architecture set either")
    message(STATUS "      PROCESSOR_ARCHITECTURE or DETOURS_TARGET_PROCESSOR.")
    message(STATUS "PROCESSOR_ARCHITECTURE: '${PROCESSOR_ARCHITECTURE}'")
    message(STATUS "DETOURS_TARGET_PROCESSOR: '${DETOURS_TARGET_PROCESSOR}'")
    message(FATAL_ERROR "Unknown target processor: ${DETOURS_TARGET_ARCHITECTURE}")
endif()

##############################################################################

set(ROOT "${CMAKE_SOURCE_DIR}")

set(INCD "${ROOT}/include")
set(LIBD "${ROOT}/lib.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")
set(BIND "${ROOT}/bin.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")
set(OBJD "${ROOT}/obj.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")

if (NOT (DETOURS_OPTION_PROCESSOR STREQUAL ""))
    set(OPTD "${ROOT}/bin.${DETOURS_OPTION_PROCESSOR}${DETOURS_CONFIG}")
endif()

set(INCDS "${ROOT}/include")

set(LIBDS "${ROOT}/lib.x86${DETOURS_CONFIG}"
          "${ROOT}/lib.x64${DETOURS_CONFIG}"
          "${ROOT}/lib.ia64${DETOURS_CONFIG}"
          "${ROOT}/lib.arm${DETOURS_CONFIG}"
          "${ROOT}/lib.arm64${DETOURS_CONFIG}")

set(BINDS "${ROOT}/bin.x86${DETOURS_CONFIG}"
          "${ROOT}/bin.x64${DETOURS_CONFIG}"
          "${ROOT}/bin.ia64${DETOURS_CONFIG}"
          "${ROOT}/bin.arm${DETOURS_CONFIG}"
          "${ROOT}/bin.arm64${DETOURS_CONFIG}")

set(OBJDS "obj.x86${DETOURS_CONFIG}"
          "obj.x64${DETOURS_CONFIG}"
          "obj.ia64${DETOURS_CONFIG}"
          "obj.arm${DETOURS_CONFIG}"
          "obj.arm64${DETOURS_CONFIG}")

# set output directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/${LIBD})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/${LIBD})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/${BIND})

##############################################################################

include_directories(${INCDS} src/include samples/syelog)

# subdirectories
subdirs(src samples)

##############################################################################
