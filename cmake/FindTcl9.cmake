# FindTcl9.cmake --
#
#	Tcl 9 for stubs-enabled extensions. Reads tclConfig.sh when there is
#	one (TCL_CONFIG, or searched for under the usual prefixes); otherwise
#	looks for tcl.h and the stub library directly (MSVC builds of Tcl).
#
#	Tcl::stubs	interface target: headers, USE_TCL_STUBS, stub library
#	Tcl::tcl	the Tcl library itself, for test programs
#	TCL_VERSION	e.g. 9.0
#	TCL_PREFIX	where Tcl is installed
#	TCLSH		interpreter matching the build, for the tests

find_file(TCL_CONFIG tclConfig.sh
    PATH_SUFFIXES lib lib/tcl9.0 lib64 lib/tcl9 lib/tcl
    DOC "tclConfig.sh of the Tcl 9 to build against")

function(_tcl_config_get var)
    file(STRINGS "${TCL_CONFIG}" line REGEX "^${var}=")
    string(REGEX REPLACE "^${var}='?([^']*)'?$" "\\1" value "${line}")
    if(CMAKE_HOST_WIN32)
	# An MSYS2 build of Tcl writes /c/... for c:/...
	string(REGEX REPLACE "(^| |-[IL])/([A-Za-z])/" "\\1\\2:/"
	    value "${value}")
    endif()
    set(_${var} "${value}" PARENT_SCOPE)
endfunction()

if(TCL_CONFIG)
    foreach(var TCL_VERSION TCL_PREFIX TCL_EXEC_PREFIX TCL_INCLUDE_SPEC
	    TCL_STUB_LIB_PATH TCL_LIB_SPEC TCL_LIBS TCL_SHLIB_SUFFIX)
	_tcl_config_get(${var})
    endforeach()
    string(REGEX MATCHALL "-I[^ ]+" incs "${_TCL_INCLUDE_SPEC}")
    list(TRANSFORM incs REPLACE "^-I" "")
    set(TCL_INCLUDE_DIR "${incs}" CACHE PATH "Tcl headers")
    set(TCL_STUB_LIBRARY "${_TCL_STUB_LIB_PATH}" CACHE FILEPATH "Tcl stub library")
    set(TCL_VERSION "${_TCL_VERSION}")
    set(TCL_PREFIX "${_TCL_PREFIX}")
    set(TCL_SHLIB_SUFFIX "${_TCL_SHLIB_SUFFIX}")
    set(_tcl_bindir "${_TCL_EXEC_PREFIX}/bin")
else()
    find_path(TCL_INCLUDE_DIR tcl.h PATH_SUFFIXES tcl9.0 tcl9 tcl)
    find_library(TCL_STUB_LIBRARY NAMES tclstub tclstub90 tclstub9.0)
    if(TCL_INCLUDE_DIR)
	file(STRINGS "${TCL_INCLUDE_DIR}/tcl.h" ver
	    REGEX "^#define TCL_(MAJOR|MINOR)_VERSION")
	string(REGEX REPLACE ".*MAJOR_VERSION[ \t]+([0-9]+).*MINOR_VERSION[ \t]+([0-9]+).*"
	    "\\1.\\2" TCL_VERSION "${ver}")
	get_filename_component(TCL_PREFIX "${TCL_INCLUDE_DIR}" DIRECTORY)
	set(_tcl_bindir "${TCL_PREFIX}/bin")
    endif()
endif()

if(TCL_VERSION)
    string(REPLACE "." "" _tcl_nodot "${TCL_VERSION}")
    set(_tcl_names tclsh${TCL_VERSION} tclsh${_tcl_nodot}
	tclsh${_tcl_nodot}${CMAKE_EXECUTABLE_SUFFIX})
    find_program(TCLSH NAMES ${_tcl_names} PATHS "${_tcl_bindir}"
	NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH DOC "tclsh to run the tests with")
    if(NOT CMAKE_CROSSCOMPILING)
	find_program(TCLSH NAMES ${_tcl_names})
    endif()
    find_library(TCL_LIBRARY NAMES tcl${TCL_VERSION} tcl${_tcl_nodot}
	HINTS "${TCL_PREFIX}/lib")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Tcl9
    REQUIRED_VARS TCL_INCLUDE_DIR TCL_STUB_LIBRARY TCL_VERSION
    VERSION_VAR TCL_VERSION)

if(Tcl9_FOUND AND NOT TARGET Tcl::stubs)
    if(TCL_VERSION VERSION_LESS 9.0)
	message(FATAL_ERROR "Tcl ${TCL_VERSION} found at ${TCL_PREFIX}; "
	    "these packages need Tcl 9 (set TCL_CONFIG)")
    endif()
    add_library(Tcl::stubs INTERFACE IMPORTED)
    target_include_directories(Tcl::stubs INTERFACE ${TCL_INCLUDE_DIR})
    target_compile_definitions(Tcl::stubs INTERFACE USE_TCL_STUBS)
    target_link_libraries(Tcl::stubs INTERFACE "${TCL_STUB_LIBRARY}")
    if(TCL_LIBRARY)
	add_library(Tcl::tcl UNKNOWN IMPORTED)
	set_target_properties(Tcl::tcl PROPERTIES
	    IMPORTED_LOCATION "${TCL_LIBRARY}"
	    INTERFACE_INCLUDE_DIRECTORIES "${TCL_INCLUDE_DIR}")
	if(_TCL_LIBS)
	    separate_arguments(libs UNIX_COMMAND "${_TCL_LIBS}")
	    # macOS: keep "-framework CoreFoundation" one item.
	    string(REPLACE "-framework;" "-framework " libs "${libs}")
	    target_link_libraries(Tcl::tcl INTERFACE ${libs})
	endif()
	# Tcl 9 is threaded; TCL_LIBS can omit -lpthread (OpenBSD: -pthread).
	target_link_libraries(Tcl::tcl INTERFACE
	    $<TARGET_NAME_IF_EXISTS:Threads::Threads>)
    endif()
endif()
