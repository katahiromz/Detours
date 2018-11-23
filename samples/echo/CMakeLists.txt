add_library(echofx${DETOURS_BITS} SHARED echofx.cpp echofx.rc echofx.def)
target_link_libraries(echofx${DETOURS_BITS} ${DEPS})
set_target_properties(echofx${DETOURS_BITS} PROPERTIES OUTPUT_NAME "echofx${DETOURS_BITS}")

add_executable(echonul echonul.cpp main.cpp echonul.def)
target_link_libraries(echonul ${DEPS} echofx${DETOURS_BITS})
