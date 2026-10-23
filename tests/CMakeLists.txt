CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

INCLUDE_DIRECTORIES( BEFORE SYSTEM "${PROJECT_SOURCE_DIR}/include" )

# We're overriding ADD_EXECUTABLE here to create our own version that does some extra stuff, like deps and linking
FUNCTION(ADD_EXAMPLE_EXECUTABLE EXE_NAME )
    ADD_EXECUTABLE(${EXE_NAME} ${ARGN})
    TARGET_LINK_LIBRARIES(${EXE_NAME} introvirt)
ENDFUNCTION()

ADD_EXAMPLE_EXECUTABLE(gdt "gdt.cc")
ADD_EXAMPLE_EXECUTABLE(idt "idt.cc")
ADD_EXAMPLE_EXECUTABLE(readmem "readmem.cc")
ADD_EXAMPLE_EXECUTABLE(readvcpu "readvcpu.cc")

# Unit tests: like ADD_EXAMPLE_EXECUTABLE, but also registered with CTest so
# `ctest` runs them. These must be self-contained (no live hypervisor), unlike
# the integration tools above.
FUNCTION(ADD_UNIT_TEST EXE_NAME )
    ADD_EXECUTABLE(${EXE_NAME} ${ARGN})
    TARGET_LINK_LIBRARIES(${EXE_NAME} introvirt)
    ADD_TEST(NAME ${EXE_NAME} COMMAND ${EXE_NAME})
ENDFUNCTION()

ADD_UNIT_TEST(introvirt_unit_tests "unit_tests.cc")
