# Fetch.cmake --
#
#	cmake -DDIR=<dir> -P cmake/Fetch.cmake
#
#	Downloads every bundled library (checking its SHA-256) and unpacks it
#	in DIR as <name>-<version>, then vendors the rustls crates into
#	DIR/cargo (needs cargo). Configure with -DTLS_SOURCES=DIR to build
#	without network access.

if(NOT DIR)
    message(FATAL_ERROR "usage: cmake -DDIR=<dir> -P cmake/Fetch.cmake")
endif()
get_filename_component(DIR "${DIR}" ABSOLUTE)
get_filename_component(root "${CMAKE_CURRENT_LIST_DIR}" DIRECTORY)
include(${CMAKE_CURRENT_LIST_DIR}/Sources.cmake)

foreach(lib IN ITEMS wolfssl mbedtls openssl)
    string(TOUPPER ${lib} L)
    set(dest ${DIR}/${lib}-${TLS_${L}_VERSION})
    if(EXISTS ${dest})
	message(STATUS "${lib}: ${dest} already there")
	continue()
    endif()
    get_filename_component(name "${TLS_${L}_URL}" NAME)
    message(STATUS "${lib}: downloading ${TLS_${L}_URL}")
    file(DOWNLOAD ${TLS_${L}_URL} ${DIR}/${name}
	EXPECTED_HASH SHA256=${TLS_${L}_SHA256} STATUS status)
    list(GET status 0 code)
    if(code)
	message(FATAL_ERROR "${lib}: download failed: ${status}")
    endif()
    # Tarballs hold one top directory; it becomes <name>-<version>.
    file(REMOVE_RECURSE ${dest}.tmp)
    file(ARCHIVE_EXTRACT INPUT ${DIR}/${name} DESTINATION ${dest}.tmp)
    file(GLOB top LIST_DIRECTORIES true ${dest}.tmp/*)
    file(RENAME ${top} ${dest})
    file(REMOVE_RECURSE ${dest}.tmp ${DIR}/${name})
endforeach()

find_program(CARGO cargo)
if(CARGO)
    message(STATUS "rustls: vendoring crates into ${DIR}/cargo")
    execute_process(COMMAND ${CARGO} vendor --locked --versioned-dirs
	    --manifest-path ${root}/rustls/Cargo.toml ${DIR}/cargo
	OUTPUT_QUIET ERROR_VARIABLE log RESULT_VARIABLE code)
    if(code)
	message(FATAL_ERROR "cargo vendor failed:\n${log}")
    endif()
else()
    message(STATUS "rustls: no cargo, crates not vendored")
endif()
message(STATUS "Done: configure with -DTLS_SOURCES=${DIR}")
