## CMakeLists.txt for Detours.
## Copyright (C) 2018 Katayama Hirofumi MZ. All Rights Reserved.
##############################################################################

if (DETOURS_SOURCE_BROWSING STREQUAL "")
    set(DETOURS_SOURCE_BROWSING 0)
endif()

##############################################################################
# DETOURS_CFLAGS

set(DETOURS_CFLAGS)

# /W4: Sets which warning level to output.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /W4)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -pedantic -Wall)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -pedantic -Wall)
endif()

# /WX: Treats all warnings as errors.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /WX)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -Werror)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -Werror)
endif()

# /Zi: Generates complete debugging information.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /Zi)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -g3 -ggdb)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -g3 -ggdb)
endif()

# /MT: Creates a multithreaded executable file using LIBCMT.lib.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /MT)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -pthread)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -pthread)
endif()

# /Gy: Enables function-level linking.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /Gy)
endif()

# /Zl: Removes default library name from .obj file (x86 only).
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /Zl)
endif()

# /Gm-: Disable minimal rebuild.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /Gm-)
endif()

# /Od: Disables optimization.
if (MSVC)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /Od)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -O0)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} -O0)
endif()

if (DETOURS_SOURCE_BROWSING EQUAL 1)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /FR)
else()
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x501)
endif()

if (DETOURS_TARGET_PROCESSOR STREQUAL "IA64")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /wd4163) # intrinsic rdtebex not available; using newer Windows headers with older compiler
endif()

if (DETOURS_WIN_7 AND DETOURS_CL_17_OR_NEWER)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /D_USING_V110_SDK71_)
elseif (DETOURS_ANALYZE)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /analyze)
endif()

##############################################################################

add_library(detours
    detours.cpp
    modules.cpp
    disasm.cpp
    image.cpp
    creatwth.cpp
    disolx86.cpp
    disolx64.cpp
    disolia64.cpp
    disolarm.cpp
    disolarm64.cpp)
target_compile_definitions(detours PRIVATE ${DETOURS_CFLAGS})

file(COPY detours.h DESTINATION ${INCD})
file(COPY detver.h DESTINATION ${INCD})

##############################################################################
