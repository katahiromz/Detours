add_library(trctcp${DETOURS_BITS} SHARED trctcp.cpp trctcp.rc trctcp.def)
target_link_libraries(trctcp${DETOURS_BITS} ${DEPS} ws2_32)
set_target_properties(trctcp${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trctcp${DETOURS_BITS}")
