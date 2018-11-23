add_library(slept${DETOURS_BITS} SHARED slept.cpp slept.rc slept.def)
target_link_libraries(slept${DETOURS_BITS} ${DEPS})
set_target_properties(slept${DETOURS_BITS} PROPERTIES OUTPUT_NAME "slept${DETOURS_BITS}")

add_library(dslept${DETOURS_BITS} SHARED dslept.cpp dslept.rc dslept.def)
target_link_libraries(dslept${DETOURS_BITS} ${DEPS})
set_target_properties(dslept${DETOURS_BITS} PROPERTIES OUTPUT_NAME "dslept${DETOURS_BITS}")

add_executable(sleepold sleepold.cpp)
target_link_libraries(sleepold ${DEPS})

add_executable(sleepnew sleepnew.cpp)
target_link_libraries(sleepnew ${DEPS} slept${DETOURS_BITS})
