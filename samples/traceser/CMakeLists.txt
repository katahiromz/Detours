add_library(trcser${DETOURS_BITS} SHARED trcser.cpp trcser.rc trcser.def)
target_link_libraries(trcser${DETOURS_BITS} ${DEPS})
set_target_properties(trcser${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trcser${DETOURS_BITS}")
