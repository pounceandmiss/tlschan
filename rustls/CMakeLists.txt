# tlschan::rustls: rustls, built by cargo into a static library that is the whole
# backend. There is no system library to use instead.
#
# Cross builds derive the Rust target from the C toolchain or take
# TLS_RUST_TARGET. With TLS_SOURCES the crates come from its cargo/ (see
# cmake/Fetch.cmake) and cargo stays offline.

find_program(CARGO cargo REQUIRED)
set(TLS_RUST_TARGET "" CACHE STRING "Rust target triple (default: derived)")

set(target ${TLS_RUST_TARGET})
if(NOT target AND CMAKE_CROSSCOMPILING)
    set(arch ${CMAKE_SYSTEM_PROCESSOR})
    string(REPLACE "arm64" "aarch64" arch "${arch}")
    if(MINGW)
	set(target ${arch}-pc-windows-gnu)
    elseif(ANDROID)
	set(target ${arch}-linux-android)
    elseif(APPLE)
	set(target ${arch}-apple-darwin)
    else()
	message(FATAL_ERROR "tlschan::rustls: set TLS_RUST_TARGET for this cross build")
    endif()
endif()

set(dir ${CMAKE_CURRENT_BINARY_DIR}/cargo)
set(env)
if(target)
    set(dir ${dir}/${target})
    string(MAKE_C_IDENTIFIER ${target} t)
    set(env CC_${t}=${CMAKE_C_COMPILER} AR_${t}=${CMAKE_AR})
    set(args --target ${target})
endif()
if(TLS_SOURCES)
    if(NOT EXISTS ${TLS_SOURCES}/cargo)
	message(FATAL_ERROR "${TLS_SOURCES}/cargo is missing; fetch it with "
	    "cmake -DDIR=${TLS_SOURCES} -P ${PROJECT_SOURCE_DIR}/cmake/Fetch.cmake")
    endif()
    list(APPEND args --offline
	--config "source.crates-io.replace-with=\"vendored\""
	--config "source.vendored.directory=\"${TLS_SOURCES}/cargo\"")
endif()
if(MSVC)
    set(lib ${dir}/release/tlschan_rustls.lib)
else()
    set(lib ${dir}/release/libtlschan_rustls.a)
endif()

# Cargo's dep-info, next to the library and named like it, lists every
# source the library was built from.
string(REGEX REPLACE "\\.[a-z]+$" ".d" depfile ${lib})
add_custom_command(OUTPUT ${lib}
    COMMAND ${CMAKE_COMMAND} -E env ${env} ${CARGO} build --release
	--manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
	--target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo ${args}
    DEPENDS Cargo.toml Cargo.lock
    DEPFILE ${depfile}
    USES_TERMINAL VERBATIM)
add_custom_target(rustls_cargo DEPENDS ${lib})

# What `cargo rustc -- --print native-static-libs` asks for.
if(WIN32)
    set(libs ws2_32 userenv ntdll bcrypt crypt32 advapi32 kernel32)
elseif(ANDROID)
    set(libs dl log m)
elseif(APPLE)
    set(libs "-framework Security" "-framework CoreFoundation" iconv m)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    set(libs Threads::Threads c++abi m util execinfo)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    set(libs bsd gcc_s network gnu)
else()
    set(libs Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

tls_package(rustls
    ARCHIVES ${lib} DEPENDS rustls_cargo LIBS ${libs})
