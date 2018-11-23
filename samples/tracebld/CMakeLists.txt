#if (COMMAND cmake_policy)
#    cmake_policy(SET CMP0003 NEW)
#endif(COMMAND cmake_policy)

add_library(trcbld${DETOURS_BITS} SHARED trcbld.cpp trcbld.rc trcbld.def)
target_link_libraries(trcbld${DETOURS_BITS} ${DEPS})
target_link_libraries(trcbld${DETOURS_BITS} ${DEPS})
set_target_properties(trcbld${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trcbld${DETOURS_BITS}")

add_executable(tracebld tracebld.cpp)
target_link_libraries(tracebld ${DEPS})
