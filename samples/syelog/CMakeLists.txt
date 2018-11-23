file(COPY syelog.h DESTINATION ${INCD})

add_library(syelog syelog.cpp)

add_executable(sltest sltest.cpp syelog.cpp)
target_link_libraries(sltest ${DEPS})

add_executable(sltestp sltestp.cpp)
target_link_libraries(sltestp ${DEPS})

add_executable(syelogd syelogd.cpp)
target_link_libraries(syelogd ${DEPS})
