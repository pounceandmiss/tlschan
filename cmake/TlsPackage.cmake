# TlsPackage.cmake --
#
#	tls_package(backend
#	    [OBJECTS objlibs...]	backend and bundled library objects
#	    [ARCHIVES files...]		prebuilt archives that belong to it
#	    [DEPENDS targets...]	targets producing those archives
#	    [LIBS libs...]		external libraries it links against
#	    [REQUIRES modules...])	pkg-config names of those, for .pc
#
#	Builds the channel layer with one backend into package tlschan::backend
#	(target and file stem tlschan_backend, init Tlschan_backend_Init): a loadable
#	module plus pkgIndex.tcl, or with BUILD_SHARED_LIBS off a static
#	archive whose only global symbol is the init function, plus a .pc
#	file. A test_backend.c next to the caller becomes the backend's C test.
#
#	The target carries TLS_NAME and, when static, TLS_INIT, TLS_ARCHIVE
#	and TLS_LIBS for tests/CMakeLists.txt, which finds it through the
#	global property TLS_BUILT. "$<0:>" in an output directory keeps
#	multi-config generators from appending a per-config subdirectory.

function(tls_package backend)
    cmake_parse_arguments(PARSE_ARGV 1 arg ""
	"" "OBJECTS;ARCHIVES;DEPENDS;LIBS;REQUIRES")
    set(ver ${PROJECT_VERSION})
    set(name tlschan::${backend})
    set(pkg tlschan_${backend})
    set(prefix Tlschan_${backend})
    set(init ${prefix}_Init)
    set(out ${PROJECT_BINARY_DIR}/lib)

    add_library(${pkg}_core OBJECT ${PROJECT_SOURCE_DIR}/generic/tls.c
	${PROJECT_SOURCE_DIR}/generic/tlsIO.c ${PROJECT_SOURCE_DIR}/generic/x509.c)
    if(WIN32)
	target_sources(${pkg}_core PRIVATE ${PROJECT_SOURCE_DIR}/generic/winroot.c)
    endif()
    target_compile_definitions(${pkg}_core PRIVATE TLS_PKG="${name}"
	TLS_INIT=${init} TLS_BACKEND="${backend}" PACKAGE_VERSION="${ver}")
    target_include_directories(${pkg}_core PRIVATE
	${PROJECT_SOURCE_DIR}/generic ${PROJECT_BINARY_DIR})
    target_link_libraries(${pkg}_core PRIVATE Tcl::stubs)
    add_dependencies(${pkg}_core tls_script)
    tls_warnings(${pkg}_core)

    set(parts)
    foreach(lib IN LISTS arg_OBJECTS)
	list(APPEND parts $<TARGET_OBJECTS:${lib}>)
    endforeach()

    if(BUILD_SHARED_LIBS)
	# Loadable module in lib/tls_<backend><ver>/ with its pkgIndex.tcl.
	if(WIN32)
	    string(REPLACE "." "" short ${ver})
	    set(file tcl9${pkg}${short})
	else()
	    set(file libtcl9${pkg}${ver})
	endif()
	set(dir ${out}/${pkg}${ver})
	add_library(${pkg} MODULE $<TARGET_OBJECTS:${pkg}_core> ${parts})
	target_link_libraries(${pkg} PRIVATE
	    ${arg_ARCHIVES} ${arg_LIBS} Tcl::stubs)
	if(arg_DEPENDS)
	    add_dependencies(${pkg} ${arg_DEPENDS})
	endif()
	set_target_properties(${pkg} PROPERTIES PREFIX "" OUTPUT_NAME ${file}
	    LIBRARY_OUTPUT_DIRECTORY ${dir}$<0:>)
	if(TCL_SHLIB_SUFFIX)
	    set_target_properties(${pkg} PROPERTIES SUFFIX ${TCL_SHLIB_SUFFIX})
	endif()
	# Export nothing but the init function, bundled libraries included.
	if(APPLE)
	    target_link_options(${pkg} PRIVATE LINKER:-exported_symbol,_${init})
	elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	    target_link_options(${pkg} PRIVATE LINKER:--exclude-libs,ALL)
	    if(MINGW)
		target_link_options(${pkg} PRIVATE -static-libgcc)
	    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
		# Shared objects there are not linked against libc: no -z defs.
		target_link_options(${pkg} PRIVATE LINKER:--as-needed)
	    else()
		target_link_options(${pkg} PRIVATE LINKER:-z,defs LINKER:--as-needed)
	    endif()
	endif()
	file(GENERATE OUTPUT ${dir}/pkgIndex.tcl CONTENT "package ifneeded \
${name} ${ver} [list load [file join $dir $<TARGET_FILE_NAME:${pkg}>] ${prefix}]\n")
	install(TARGETS ${pkg} LIBRARY DESTINATION ${TLS_INSTALL_LIBDIR}/${pkg}${ver})
	install(FILES ${dir}/pkgIndex.tcl
	    DESTINATION ${TLS_INSTALL_LIBDIR}/${pkg}${ver})
    elseif(MSVC)
	# No relocatable link here: a plain archive, symbols not hidden.
	add_library(${pkg} STATIC $<TARGET_OBJECTS:${pkg}_core> ${parts})
	set_target_properties(${pkg} PROPERTIES OUTPUT_NAME tcl9${pkg}${ver}
	    ARCHIVE_OUTPUT_DIRECTORY ${out}$<0:> TLS_INIT ${prefix}
	    TLS_ARCHIVE ${out}/tcl9${pkg}${ver}.lib TLS_LIBS "${arg_ARCHIVES};${arg_LIBS}")
	install(TARGETS ${pkg} ARCHIVE DESTINATION ${TLS_INSTALL_LIBDIR})
    else()
	# Static: one prelinked object in an archive, see Prelink.cmake.
	set(archive ${out}/${CMAKE_STATIC_LIBRARY_PREFIX}tcl9${pkg}${ver}${CMAKE_STATIC_LIBRARY_SUFFIX})
	add_custom_command(OUTPUT ${archive}
	    COMMAND ${CMAKE_COMMAND} -DLD=${CMAKE_LINKER} -DOBJCOPY=${CMAKE_OBJCOPY}
		-DAR=${CMAKE_AR} -DAPPLE=${APPLE} -DINIT=${init} -DOUT=${archive}
		-DMINGW=${MINGW} -DNM=${CMAKE_NM} -DOBJDUMP=${CMAKE_OBJDUMP}
		"-DINPUTS=$<TARGET_OBJECTS:${pkg}_core>;${parts};${arg_ARCHIVES}"
		-P ${PROJECT_SOURCE_DIR}/cmake/Prelink.cmake
	    DEPENDS ${pkg}_core ${arg_OBJECTS} ${arg_DEPENDS} ${arg_ARCHIVES}
		$<TARGET_OBJECTS:${pkg}_core> ${parts}
		${PROJECT_SOURCE_DIR}/cmake/Prelink.cmake
	    COMMENT "Prelinking ${archive}" VERBATIM)
	add_custom_target(${pkg} ALL DEPENDS ${archive})
	set_target_properties(${pkg} PROPERTIES
	    TLS_INIT ${prefix} TLS_ARCHIVE ${archive} TLS_LIBS "${arg_LIBS}")

	# Libraries a static consumer must add, in pkg-config form.
	set(private)
	foreach(lib IN LISTS arg_LIBS)
	    if(lib STREQUAL "Threads::Threads")
		list(APPEND private ${CMAKE_THREAD_LIBS_INIT})
	    elseif(lib MATCHES "^-")
		list(APPEND private "${lib}")
	    elseif(NOT TARGET ${lib})
		list(APPEND private -l${lib})
	    endif()
	endforeach()
	list(JOIN private " " private)
	list(JOIN arg_REQUIRES " " requires)
	file(WRITE ${out}/pkgconfig/tcl9${pkg}.pc "\
prefix=\${pcfiledir}/../..
libdir=\${prefix}/${TLS_INSTALL_LIBDIR}

Name: tcl9${pkg}
Description: Tcl package ${name} (static); initialize with ${init}
Version: ${ver}
Requires.private: ${requires}
Libs: -L\${libdir} -ltcl9${pkg}${ver}
Libs.private: ${private}
")
	install(FILES ${archive} DESTINATION ${TLS_INSTALL_LIBDIR})
	install(FILES ${out}/pkgconfig/tcl9${pkg}.pc
	    DESTINATION ${TLS_INSTALL_LIBDIR}/pkgconfig)
    endif()
    set_target_properties(${pkg} PROPERTIES TLS_NAME ${name})
    set_property(GLOBAL APPEND PROPERTY TLS_BUILT ${pkg})

    # The C harnesses are POSIX programs (sockets, threads).
    if(BUILD_TESTING AND NOT WIN32 AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_backend.c)
	add_executable(${pkg}_harness test_backend.c)
	target_include_directories(${pkg}_harness PRIVATE ${PROJECT_SOURCE_DIR}/generic)
	target_link_libraries(${pkg}_harness PRIVATE
	    ${arg_OBJECTS} ${arg_ARCHIVES} ${arg_LIBS})
	if(arg_DEPENDS)
	    add_dependencies(${pkg}_harness ${arg_DEPENDS})
	endif()
	set(certs ${PROJECT_SOURCE_DIR}/tests/certs)
	set(net)
	if(NOT TLS_TEST_NETWORK)
	    set(net -nonet)
	endif()
	add_test(NAME ${backend}-harness COMMAND ${pkg}_harness ${certs} ${certs} ${net}
	    WORKING_DIRECTORY ${certs})
	set_tests_properties(${backend}-harness PROPERTIES
	    ENVIRONMENT "${TLS_TEST_ENV}")
    endif()
endfunction()
