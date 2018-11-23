add_library(trcapi${DETOURS_BITS} SHARED trcapi.cpp trcapi.rc)
target_link_libraries(trcapi${DETOURS_BITS} ${DEPS})

add_executable(testapi testapi.cpp trcapi.cpp _win32.cpp)
target_link_libraries(testapi ${DEPS})
