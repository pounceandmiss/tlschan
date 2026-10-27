# tlschan::openssl: OpenSSL 3. AUTO takes the system OpenSSL for shared builds and
# bundles the 3.5 LTS release for static ones (needs perl).

set(TLS_OPENSSL AUTO CACHE STRING "OpenSSL: AUTO, BUNDLED or SYSTEM")
set_property(CACHE TLS_OPENSSL PROPERTY STRINGS AUTO BUNDLED SYSTEM)
set(TLS_OPENSSL_CONFIGURE "" CACHE STRING
    "Extra arguments for the bundled OpenSSL's Configure, e.g. a target")

add_library(openssl_backend OBJECT backend.c)
target_include_directories(openssl_backend PUBLIC ${PROJECT_SOURCE_DIR}/generic)
tls_warnings(openssl_backend)

if(TLS_OPENSSL STREQUAL "SYSTEM")
    find_package(OpenSSL 3.0 REQUIRED)
elseif(TLS_OPENSSL STREQUAL "AUTO" AND BUILD_SHARED_LIBS)
    find_package(OpenSSL 3.0)
endif()

if(OPENSSL_FOUND)
    message(STATUS "tlschan::openssl: OpenSSL ${OPENSSL_VERSION}")
    target_link_libraries(openssl_backend PUBLIC OpenSSL::SSL)
    tls_package(openssl OBJECTS openssl_backend
	LIBS OpenSSL::SSL OpenSSL::Crypto ${TLS_OS_LIBS} REQUIRES openssl)
    return()
endif()

include(ExternalProject)
find_package(Perl REQUIRED)

# Configure picks the native target itself; cross builds need naming one.
set(configure ${TLS_OPENSSL_CONFIGURE})
if(CMAKE_CROSSCOMPILING AND MINGW)
    string(REGEX REPLACE "gcc(\\.exe)?$" "" cross ${CMAKE_C_COMPILER})
    list(PREPEND configure mingw64 --cross-compile-prefix=${cross})
    set(cc gcc)
    set(ar ar)
elseif(APPLE)
    list(PREPEND configure darwin64-${CMAKE_SYSTEM_PROCESSOR}-cc)
    # The real compiler (not the /usr/bin/cc shim) needs the SDK named.
    if(CMAKE_OSX_SYSROOT)
	list(APPEND configure -isysroot ${CMAKE_OSX_SYSROOT})
    endif()
    if(CMAKE_OSX_DEPLOYMENT_TARGET)
	list(APPEND configure -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
    endif()
    set(cc ${CMAKE_C_COMPILER})
    set(ar ${CMAKE_AR})
elseif(MSVC)
    list(PREPEND configure VC-WIN64A)
    set(cc cl)
    set(ar lib)
else()
    set(cc ${CMAKE_C_COMPILER})
    set(ar ${CMAKE_AR})
endif()
if(MSVC)
    set(make nmake)
    set(libs libssl.lib libcrypto.lib)
else()
    find_program(make NAMES gmake make REQUIRED)
    cmake_host_system_information(RESULT jobs QUERY NUMBER_OF_LOGICAL_CORES)
    set(make ${make} -j${jobs})
    set(libs libssl.a libcrypto.a)
endif()

set(prefix ${CMAKE_CURRENT_BINARY_DIR}/openssl)
list(TRANSFORM libs PREPEND ${prefix}/lib/)
file(MAKE_DIRECTORY ${prefix}/include)

tls_fetch(openssl)

ExternalProject_Add(openssl_bundled
    SOURCE_DIR ${openssl_SOURCE_DIR}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CC=${cc} AR=${ar}
	${PERL_EXECUTABLE} ${openssl_SOURCE_DIR}/Configure ${configure}
	no-shared no-module no-dso no-engine no-legacy no-tests no-docs
	no-apps no-ssl3 no-comp no-ui-console
	--prefix=${prefix} --libdir=lib --openssldir=/etc/ssl -fPIC
    BUILD_COMMAND ${make} build_libs
    INSTALL_COMMAND ${make} install_dev
    BUILD_BYPRODUCTS ${libs}
    USES_TERMINAL_BUILD ON)

add_library(openssl_headers INTERFACE)
target_include_directories(openssl_headers INTERFACE ${prefix}/include)
add_dependencies(openssl_headers openssl_bundled)
target_link_libraries(openssl_backend PUBLIC openssl_headers)

tls_package(openssl OBJECTS openssl_backend
    ARCHIVES ${libs} DEPENDS openssl_bundled LIBS ${TLS_OS_LIBS})
