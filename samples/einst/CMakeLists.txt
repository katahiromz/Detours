add_library(edll1x${DETOURS_BITS} SHARED edll1x.cpp)
set_target_properties(edll1x${DETOURS_BITS} PROPERTIES OUTPUT_NAME "edll1x${DETOURS_BITS}")
target_link_libraries(edll1x${DETOURS_BITS} ${DEPS})
if (MSVC)
    set_target_properties(edll1x${DETOURS_BITS} PROPERTIES LINK_FLAGS "/base:0x7100000")
else()
    set_target_properties(edll1x${DETOURS_BITS} PROPERTIES LINK_FLAGS "-Ttext 7100000")
endif()

add_library(edll2x${DETOURS_BITS} SHARED edll2x.cpp)
set_target_properties(edll2x${DETOURS_BITS} PROPERTIES OUTPUT_NAME "edll2x${DETOURS_BITS}")
target_link_libraries(edll2x${DETOURS_BITS} ${DEPS})
if (MSVC)
    set_target_properties(edll2x${DETOURS_BITS} PROPERTIES LINK_FLAGS "/base:0x7200000")
else()
    set_target_properties(edll2x${DETOURS_BITS} PROPERTIES LINK_FLAGS "-Ttext 7200000")
endif()

add_library(edll3x${DETOURS_BITS} SHARED edll3x.cpp)
set_target_properties(edll3x${DETOURS_BITS} PROPERTIES OUTPUT_NAME "edll3x${DETOURS_BITS}")
target_link_libraries(edll3x${DETOURS_BITS} ${DEPS})
if (MSVC)
    set_target_properties(edll3x${DETOURS_BITS} PROPERTIES LINK_FLAGS "/base:0x7300000")
else()
    set_target_properties(edll3x${DETOURS_BITS} PROPERTIES LINK_FLAGS "-Ttext 7300000")
endif()

add_executable(einst WIN32 einst.cpp)
target_link_libraries(einst ${DEPS} edll1x${DETOURS_BITS} edll2x${DETOURS_BITS} edll3x${DETOURS_BITS})
