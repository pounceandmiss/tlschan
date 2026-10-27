# Tcl 9 TLS packages over four backends sharing one channel layer:
#
#	tlschan::wolfssl  tlschan::rustls  tlschan::mbedtls  tlschan::openssl
#	and tlschan, which loads whichever of them is available
#
#   cmake -B build [-DTLS_BACKENDS="openssl;mbedtls"|all] [-DTCL_CONFIG=...]
#   cmake --build build && ctest --test-dir build && cmake --install build
#
# BUILD_SHARED_LIBS=OFF builds static archives for embedding instead of
# loadable modules. TLS_WOLFSSL, TLS_MBEDTLS and TLS_OPENSSL choose between
# the system library and a pinned bundled release (see README.md).

cmake_minimum_required(VERSION 3.24...4.0)
project(tlschan VERSION 0.1.0 LANGUAGES C)

set(CMAKE_FIND_PACKAGE_TARGETS_GLOBAL ON)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Tcl9 REQUIRED)
find_package(Threads)
include(CTest)
include(FetchContent)

option(BUILD_SHARED_LIBS "Loadable Tcl modules; OFF for static archives" ON)
set(TLS_BACKENDS "" CACHE STRING "Backends to build, each as package \
tlschan::<backend>: some of wolfssl rustls mbedtls openssl, or all; empty \
picks one over a system library")
option(TLS_TEST_NETWORK "Let the tests reach servers on the Internet" OFF)
set(TLS_SOURCES "" CACHE PATH
    "Directory filled by cmake/Fetch.cmake, for building without network")
include(Sources)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${TCL_PREFIX}" CACHE PATH "Install prefix" FORCE)
endif()
set(TLS_INSTALL_LIBDIR lib CACHE STRING "Directory under the prefix for packages")

set(TLS_SANITIZE "" CACHE STRING "Sanitizers for everything, e.g. address,undefined")
set(TLS_TEST_ENV)
if(TLS_SANITIZE)
    add_compile_options(-fsanitize=${TLS_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${TLS_SANITIZE})
    list(APPEND TLS_TEST_ENV ASAN_OPTIONS=detect_leaks=0
	UBSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/ubsan.supp:print_stacktrace=1)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Our own sources; the bundled libraries keep their own warning levels.
function(tls_warnings target)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options(${target} PRIVATE
	    -Wall -Wextra -Wno-unused-parameter)
    endif()
endfunction()

# System libraries each platform needs for sockets, crypto and trust stores.
if(WIN32)
    set(TLS_OS_LIBS ws2_32 crypt32 bcrypt advapi32 user32)
elseif(APPLE)
    set(TLS_OS_LIBS "-framework Security" "-framework CoreFoundation")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    set(TLS_OS_LIBS network)		# pthread and dl are in libroot
else()
    set(TLS_OS_LIBS Threads::Threads ${CMAKE_DL_LIBS})
endif()

# generic/tls.tcl, compiled in as a string.
add_custom_command(OUTPUT tlsScript.h
    COMMAND ${CMAKE_COMMAND} -DIN=${PROJECT_SOURCE_DIR}/generic/tls.tcl
	-DOUT=${PROJECT_BINARY_DIR}/tlsScript.h -DNAME=tlsScript
	-P ${PROJECT_SOURCE_DIR}/cmake/Embed.cmake
    DEPENDS generic/tls.tcl cmake/Embed.cmake)
add_custom_target(tls_script DEPENDS tlsScript.h)

include(TlsPackage)

# Unless asked for more, one backend over a library the system maintains:
# nothing gets downloaded and compiled in by default.
if(TLS_BACKENDS STREQUAL "")
    find_package(OpenSSL 3.0 QUIET)
    if(OPENSSL_FOUND)
	set(backends openssl)
	set(TLS_OPENSSL SYSTEM)
    else()
	find_package(MbedTLS 3.6...<4 CONFIG QUIET
	    PATHS /usr/lib/mbedtls3/cmake /usr/local/lib/mbedtls3/cmake)
	if(NOT MbedTLS_FOUND)
	    message(FATAL_ERROR "No system OpenSSL 3 or Mbed TLS 3.6 found. "
		"Install one (or point CMAKE_PREFIX_PATH at it), or choose "
		"backends that compile their library in: -DTLS_BACKENDS=wolfssl "
		"or rustls, or all of them with -DTLS_BACKENDS=all.")
	endif()
	set(backends mbedtls)
	set(TLS_MBEDTLS SYSTEM)
    endif()
    message(STATUS "Building tlschan::${backends} over the system library "
	"(-DTLS_BACKENDS=... for others)")
elseif(TLS_BACKENDS STREQUAL "all")
    set(backends wolfssl rustls mbedtls openssl)
else()
    set(backends ${TLS_BACKENDS})
endif()
foreach(backend IN LISTS backends)
    if(NOT backend MATCHES "^(wolfssl|rustls|mbedtls|openssl)$")
	message(FATAL_ERROR "TLS_BACKENDS: unknown backend ${backend}")
    endif()
    add_subdirectory(${backend})
endforeach()

# The umbrella package tlschan: plain Tcl, loads whichever backend is there.
set(umbrella ${PROJECT_BINARY_DIR}/lib/tlschan${PROJECT_VERSION})
configure_file(generic/tlschan.tcl ${umbrella}/tlschan.tcl @ONLY)
file(WRITE ${umbrella}/pkgIndex.tcl "package ifneeded tlschan \
${PROJECT_VERSION} [list source [file join $dir tlschan.tcl]]\n")
install(FILES ${umbrella}/tlschan.tcl ${umbrella}/pkgIndex.tcl
    DESTINATION ${TLS_INSTALL_LIBDIR}/tlschan${PROJECT_VERSION})

# The reference, tlschan(n). doc/tlschan.n, .md and .html are generated
# from doc/tlschan.man and kept in the tree; `doc` regenerates them
# (tcllib's dtplite).
include(GNUInstallDirs)
install(FILES doc/tlschan.n DESTINATION ${CMAKE_INSTALL_MANDIR}/mann)
find_program(DTPLITE dtplite)
if(DTPLITE)
    add_custom_target(doc
	COMMAND ${DTPLITE} -o ${PROJECT_SOURCE_DIR}/doc/tlschan.n nroff
	    ${PROJECT_SOURCE_DIR}/doc/tlschan.man
	COMMAND ${DTPLITE} -o ${PROJECT_SOURCE_DIR}/doc/tlschan.md markdown
	    ${PROJECT_SOURCE_DIR}/doc/tlschan.man
	COMMAND ${DTPLITE} -o ${PROJECT_SOURCE_DIR}/doc/tlschan.html html
	    ${PROJECT_SOURCE_DIR}/doc/tlschan.man
	COMMENT "Rendering doc/tlschan.n, .md and .html" VERBATIM)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
