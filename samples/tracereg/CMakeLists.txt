add_library(trcreg${DETOURS_BITS} SHARED trcreg.cpp trcreg.rc trcreg.def)
target_link_libraries(trcreg${DETOURS_BITS} ${DEPS})
set_target_properties(trcreg${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trcreg${DETOURS_BITS}")
