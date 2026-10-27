# tlschan::mbedtls: Mbed TLS 3.6. AUTO takes an installed 3.6 for shared builds and
# bundles it for static ones; SYSTEM also suits zippy, whose shared copy is
# found through CMAKE_PREFIX_PATH and brings its own configuration along.

set(TLS_MBEDTLS AUTO CACHE STRING "Mbed TLS: AUTO, BUNDLED or SYSTEM")
set_property(CACHE TLS_MBEDTLS PROPERTY STRINGS AUTO BUNDLED SYSTEM)

add_library(mbedtls_backend OBJECT backend.c)
target_include_directories(mbedtls_backend PUBLIC ${PROJECT_SOURCE_DIR}/generic)
tls_warnings(mbedtls_backend)

if(TLS_MBEDTLS STREQUAL "SYSTEM"
	OR (TLS_MBEDTLS STREQUAL "AUTO" AND BUILD_SHARED_LIBS))
    if(TLS_MBEDTLS STREQUAL "SYSTEM")
	set(required REQUIRED)
    endif()
    # Distributions that also ship 4.x keep 3.6 aside, e.g. Arch's mbedtls3.
    find_package(MbedTLS 3.6...<4 CONFIG ${required}
	PATHS /usr/lib/mbedtls3/cmake /usr/local/lib/mbedtls3/cmake)
endif()

if(MbedTLS_FOUND)
    message(STATUS "tlschan::mbedtls: Mbed TLS ${MbedTLS_VERSION} from ${MbedTLS_DIR}")
    set(mbedtls MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
    target_link_libraries(mbedtls_backend PUBLIC ${mbedtls})
    tls_package(mbedtls OBJECTS mbedtls_backend
	LIBS ${mbedtls} ${TLS_OS_LIBS} REQUIRES mbedtls mbedx509 mbedcrypto)
    return()
endif()

tls_fetch(mbedtls)

# Modules the configuration leaves out compile to nothing.
file(GLOB sources ${mbedtls_SOURCE_DIR}/library/*.c)
add_library(mbedtls_bundled OBJECT ${sources})
target_include_directories(mbedtls_bundled PUBLIC ${mbedtls_SOURCE_DIR}/include)
target_compile_definitions(mbedtls_bundled PUBLIC
    "MBEDTLS_USER_CONFIG_FILE=\"${CMAKE_CURRENT_SOURCE_DIR}/config.h\"")
set_source_files_properties(${sources} PROPERTIES
    OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/config.h)
target_link_libraries(mbedtls_backend PUBLIC mbedtls_bundled)

tls_package(mbedtls
    OBJECTS mbedtls_backend mbedtls_bundled LIBS ${TLS_OS_LIBS})
