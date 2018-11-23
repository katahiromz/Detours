if (DETOURS_TARGET_PROCESSOR STREQUAL "X86")
    add_executable(disas WIN32 disas.cpp x86.cpp)
    target_link_libraries(disas ${DEPS})
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "X64")
    add_custom_command(
        OUTPUT  disasm.obj
        COMMAND ${ASM} ${AFLAGS} /Fo$(OBJD)\disasm.obj /Fl$(OBJD)\x64.lst x64.asm
        DEPENDS x64.asm)
    add_executable(disas WIN32 disas.cpp)
    target_link_libraries(disas ${DEPS} disasm.obj)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "IA64")
    add_custom_command(
        OUTPUT  disasm.obj
        COMMAND ${ASM} ${AFLAGS} /Fo$(OBJD)\disasm.obj /Fl$(OBJD)\ia64.lst ia64.asm
        DEPENDS ia64.asm)
    add_executable(disas WIN32 disas.cpp)
    target_link_libraries(disas ${DEPS} disasm.obj)
elseif (DETOURS_TARGET_PROCESSOR STREQUAL "ARM")
    add_custom_command(
        OUTPUT  disasm.obj
        COMMAND ${ASM} ${AFLAGS} /Fo$(OBJD)\disasm.obj /Fl$(OBJD)\arm.lst arm.asm
        DEPENDS arm.asm)
    add_executable(disas WIN32 disas.cpp)
    target_link_libraries(disas ${DEPS} disasm.obj)
endif()
