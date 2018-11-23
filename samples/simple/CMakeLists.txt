add_library(simple${DETOURS_BITS} SHARED simple.cpp simple.def)
target_link_libraries(simple${DETOURS_BITS} ${DEPS})

add_executable(sleep5 sleep5.cpp)
target_link_libraries(sleep5 ${DEPS})
