if (COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_library(trcapi${DETOURS_BITS} SHARED trcapi.cpp trcapi.rc trcapi.def)
target_link_libraries(trcapi${DETOURS_BITS} ${DEPS} ws2_32)

add_executable(testapi testapi.cpp)
target_link_libraries(testapi ${DEPS} ws2_32)
