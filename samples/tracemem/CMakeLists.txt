add_library(trcmem${DETOURS_BITS} SHARED trcmem.cpp trcmem.rc trcmem.def)
target_link_libraries(trcmem${DETOURS_BITS} ${DEPS})
set_target_properties(trcmem${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trcmem${DETOURS_BITS}")
