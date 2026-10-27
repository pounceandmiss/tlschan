# The Tcl test suite once per package. Static packages are tested through
# a tclsh with all of them linked in, which also proves they coexist.
# Plus the certificate decoder against `openssl x509`, where both exist.

get_property(packages GLOBAL PROPERTY TLS_BUILT)

set(env ${TLS_TEST_ENV})
if(TLS_TEST_NETWORK)
    list(APPEND env TLS_NETWORK=1)
endif()
if(TLS_SANITIZE MATCHES "address" AND BUILD_SHARED_LIBS)
    # A plain tclsh loading instrumented modules needs the runtime first.
    execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=libasan.so
	OUTPUT_VARIABLE asan OUTPUT_STRIP_TRAILING_WHITESPACE)
    list(APPEND env LD_PRELOAD=${asan})
endif()

if(BUILD_SHARED_LIBS)
    if(NOT TCLSH)
	message(WARNING "No tclsh found: the Tcl tests are skipped")
	return()
    endif()
    set(tclsh ${CMAKE_CROSSCOMPILING_EMULATOR} ${TCLSH})
    list(APPEND env TCLLIBPATH=${PROJECT_BINARY_DIR}/lib)
else()
    if(NOT TARGET Tcl::tcl)
	message(WARNING "No Tcl library to link a test shell: Tcl tests skipped")
	return()
    endif()
    set(registry)
    foreach(pkg IN LISTS packages)
	get_target_property(init ${pkg} TLS_INIT)
	get_target_property(archive ${pkg} TLS_ARCHIVE)
	get_target_property(libs ${pkg} TLS_LIBS)
	get_target_property(name ${pkg} TLS_NAME)
	string(APPEND registry "PKG(\"${name}\", ${init})\n")
	list(APPEND archives ${archive})
	list(APPEND deplibs ${libs})
    endforeach()
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/packages.h "${registry}")

    add_executable(tlstclsh tclsh.c)
    add_dependencies(tlstclsh ${packages})
    target_include_directories(tlstclsh PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_definitions(tlstclsh PRIVATE VERSION="${PROJECT_VERSION}"
	LIBDIR="${PROJECT_BINARY_DIR}/lib")
    target_link_libraries(tlstclsh PRIVATE
	${archives} ${deplibs} Tcl::tcl ${TCL_STUB_LIBRARY})
    set(tclsh $<TARGET_FILE:tlstclsh>)
endif()

# Own scratch directory each, so the suites can run in parallel.
foreach(pkg IN LISTS packages)
    get_target_property(name ${pkg} TLS_NAME)
    string(REPLACE "tlschan::" "" test ${name})
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${test})
    add_test(NAME ${test} COMMAND ${tclsh} ${CMAKE_CURRENT_SOURCE_DIR}/all.tcl
	-tmpdir ${CMAKE_CURRENT_BINARY_DIR}/${test})
    set_tests_properties(${test} PROPERTIES
	ENVIRONMENT "TLS_PACKAGE=${name};${env}" TIMEOUT 600)
    if(CMAKE_CROSSCOMPILING_EMULATOR)
	# Emulators skew the CPU-time checks when run side by side.
	set_tests_properties(${test} PROPERTIES RUN_SERIAL ON)
    endif()
    if(WIN32 AND NOT BUILD_SHARED_LIBS AND NOT CMAKE_CROSSCOMPILING)
	# tlstclsh needs tcl90.dll, which Windows finds on PATH only.
	set_tests_properties(${test} PROPERTIES ENVIRONMENT_MODIFICATION
	    "PATH=path_list_prepend:${TCL_PREFIX}/bin")
    endif()
endforeach()

# The decoder test links Tcl itself and libcrypto for reference digests.
find_program(OPENSSL_CLI openssl)
find_package(OpenSSL COMPONENTS Crypto QUIET)
if(TARGET Tcl::tcl AND OPENSSL_CLI AND OpenSSL_FOUND
	AND NOT CMAKE_CROSSCOMPILING)
    add_executable(test_x509 x509/test_x509.c ${PROJECT_SOURCE_DIR}/generic/x509.c)
    target_include_directories(test_x509 PRIVATE ${PROJECT_SOURCE_DIR}/generic)
    target_link_libraries(test_x509 PRIVATE Tcl::tcl OpenSSL::Crypto)
    add_test(NAME x509 COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/x509/run.sh
	$<TARGET_FILE:test_x509> 500)
    set_tests_properties(x509 PROPERTIES ENVIRONMENT "SYSCERTS=0;OPENSSL=${OPENSSL_CLI};${TLS_TEST_ENV}")
    if(WIN32)
	# test_x509 needs tcl90.dll, which Windows finds on PATH only.
	set_tests_properties(x509 PROPERTIES ENVIRONMENT_MODIFICATION
	    "PATH=path_list_prepend:${TCL_PREFIX}/bin")
    endif()
endif()
