if (MSVC)
    add_executable(excep excep.cpp firstexc.cpp)
    target_link_libraries(excep ${DEPS} /entry:WinMainCRTStartup)
endif()
