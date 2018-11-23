##  Common CMakeLists.txt for Detours test programs.
##  Copyright (C) Katayama Hirofumi MZ.  All rights reserved.
##############################################################################

if (NOT DEFINED CLIB)
    set(CLIB /MT)
endif()

set(DETOURS_SAMPLE_AFLAGS /nologo /Zi /c /Fl)
set(DETOURS_SAMPLE_CFLAGS /nologo /Zi ${CLIB} /Gm- /W4 /WX /Od)

if (DETOURS_SOURCE_BROWSING EQUAL 1)
    set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /FR)
else()
    set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /I${INCD})
endif()

if (DEFINED DETOURS_WIN_7 AND DEFINED DETOURS_CL_17_OR_NEWER)
    set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /D_USING_V110_SDK71_)
endif()

if (DETOURS_TARGET_PROCESSOR STREQUAL "X86")
    set(ASM ml)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "X64")
    set(ASM ml64)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "IA64")
    set(ASM ias)
    set(DETOURS_SAMPLE_AFLAGS -F COFF32_PLUS)
    set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /wd4163) # intrinsic rdtebex not available; using newer Windows headers with older compiler
    #set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /wd4996 /wd4068)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "ARM")
    set(ASM armasm)
    set(DETOURS_SAMPLE_AFLAGS -coff_thumb2_only)
    set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /D_ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE)

    # redundant with windows.h except for midl proxies
    if (DETOURS_TARGET_PROCESSOR STREQUAL "X64")
        set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /D_AMD64_)
    else()
        set(DETOURS_SAMPLE_CFLAGS ${DETOURS_SAMPLE_CFLAGS} /D_${DETOURS_TARGET_PROCESSOR}_)
    endif()
endif()

set(DEPS syelog detours)
set(LIBS ${DEPS})

##############################################################################

add_definitions(${DETOURS_SAMPLE_CFLAGS})

subdirs(syelog traceapi)
