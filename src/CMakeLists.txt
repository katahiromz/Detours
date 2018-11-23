## CMakeLists.txt for Detours.
## Copyright (C) 2018 Katayama Hirofumi MZ. All Rights Reserved.
##############################################################################

if (DETOURS_SOURCE_BROWSING STREQUAL "")
    set(DETOURS_SOURCE_BROWSING 0)
endif()

set(DETOURS_CFLAGS /W4 /WX /Zi /MT /Gy /Gm- /Zl /Od)

if (DETOURS_SOURCE_BROWSING EQUAL 1)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /FR)
else()
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x501)
endif()

if (DETOURS_TARGET_PROCESSOR STREQUAL "IA64")
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /wd4163) # intrinsic rdtebex not available; using newer Windows headers with older compiler
endif()

if (DEFINED DETOURS_WIN_7 AND DEFINED DETOURS_CL_17_OR_NEWER)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /D_USING_V110_SDK71_)
elseif (DEFINED DETOURS_ANALYZE)
    set(DETOURS_CFLAGS ${DETOURS_CFLAGS} /analyze)
endif()

##############################################################################

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
    disolarm64.cpp
    uimports.cpp)
target_compile_definitions(detours PRIVATE ${DETOURS_CFLAGS})

file(COPY detours.h DESTINATION ${INCD})
file(COPY detver.h DESTINATION ${INCD})

##############################################################################
