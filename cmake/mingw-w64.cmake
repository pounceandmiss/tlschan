# Cross toolchain for 64-bit Windows with MinGW-w64; tests run under wine.
#
#   cmake -B build-win --toolchain cmake/mingw-w64.cmake \
#	-DTCL_CONFIG=<MinGW Tcl 9>/lib/tclConfig.sh

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

find_program(WINE wine)
if(WINE)
    set(CMAKE_CROSSCOMPILING_EMULATOR ${WINE})
endif()
