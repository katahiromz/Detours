# CMakeLists.txt --- CMake project settings
#    ex) cmake -G "Visual Studio 9 2008"
#    ex) cmake -DCMAKE_BUILD_TYPE=Release -G "MSYS Makefiles"
##############################################################################

# CMake minimum version
cmake_minimum_required(VERSION 3.13)

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
    add_link_options(/NODEFAULTLIB:libcmtd)
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
#set(DETOURS_TARGET_PROCESSOR "X64")
#set(DETOURS_TARGET_PROCESSOR "IA64")
#set(DETOURS_TARGET_PROCESSOR "ARM")
#set(DETOURS_TARGET_PROCESSOR "ARM64")

# PROCESSOR_ARCHITECTURE
set(PROCESSOR_ARCHITECTURE "X86")
#set(PROCESSOR_ARCHITECTURE "X64")
#set(PROCESSOR_ARCHITECTURE "IA64")
#set(PROCESSOR_ARCHITECTURE "ARM")
#set(PROCESSOR_ARCHITECTURE "ARM64")

# PROCESSOR_ARCHITEW6432
set(PROCESSOR_ARCHITEW6432 "")
#set(PROCESSOR_ARCHITEW6432 "AMD64")

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

set(ROOT ${CMAKE_SOURCE_DIR})

set(INCD "${CMAKE_BINARY_DIR}/include")
set(LIBD "${CMAKE_BINARY_DIR}/lib.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")
set(BIND "${CMAKE_BINARY_DIR}/bin.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")
set(OBJD "${CMAKE_BINARY_DIR}/obj.${DETOURS_TARGET_PROCESSOR}${DETOURS_CONFIG}")

if (NOT (DETOURS_OPTION_PROCESSOR STREQUAL ""))
    set(OPTD "${CMAKE_BINARY_DIR}/bin.${DETOURS_OPTION_PROCESSOR}${DETOURS_CONFIG}")
endif()

set(INCDS "${CMAKE_BINARY_DIR}/include")

set(LIBDS "${CMAKE_BINARY_DIR}/lib.x86${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.x64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.ia64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.arm${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/lib.arm64${DETOURS_CONFIG}")

set(BINDS "${CMAKE_BINARY_DIR}/bin.x86${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.x64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.ia64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.arm${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/bin.arm64${DETOURS_CONFIG}")

set(OBJDS "${CMAKE_BINARY_DIR}/obj.x86${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/obj.x64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/obj.ia64${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/obj.arm${DETOURS_CONFIG}"
          "${CMAKE_BINARY_DIR}/obj.arm64${DETOURS_CONFIG}")

if (NOT (EXISTS "${INCD}"))
    file(MAKE_DIRECTORY "${INCD}")
    message(STATUS "Created ${INCD}")
endif()
if (NOT (EXISTS "${LIBD}"))
    file(MAKE_DIRECTORY "${LIBD}")
    message(STATUS "Created ${LIBD}")
endif()
if (NOT (EXISTS "${BIND}"))
    file(MAKE_DIRECTORY "${BIND}")
    message(STATUS "Created ${BIND}")
endif()
if (NOT (EXISTS "${OBJD}"))
    file(MAKE_DIRECTORY "${OBJD}")
    message(STATUS "Created ${OBJD}")
endif()

# set output directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIBD})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBD})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIND})

##############################################################################

include_directories(${INCDS} samples/syelog)

# subdirectories
subdirs(src samples)

##############################################################################
