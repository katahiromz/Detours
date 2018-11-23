add_library(trclnk${DETOURS_BITS} SHARED trclnk.cpp trclnk.rc trclnk.def)
target_link_libraries(trclnk${DETOURS_BITS} ${DEPS})
set_target_properties(trclnk${DETOURS_BITS} PROPERTIES OUTPUT_NAME "trclnk${DETOURS_BITS}")
