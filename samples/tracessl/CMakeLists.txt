add_library(trcssl${DETOURS_BITS} SHARED trcssl.cpp trcssl.rc trcssl.def)
target_link_libraries(trcssl${DETOURS_BITS} ${DEPS} ws2_32 secur32)
set_target_properties(trcssl${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trcssl${DETOURS_BITS}")
