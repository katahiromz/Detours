add_library(wrotei${DETOURS_BITS} SHARED wrotei.cpp wrotei.rc wrotei.def)
target_link_libraries(wrotei${DETOURS_BITS} ${DEPS})

add_executable(comeasy comeasy.cpp)
target_link_libraries(comeasy ${DEPS})
