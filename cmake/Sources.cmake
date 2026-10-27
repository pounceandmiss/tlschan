# Sources.cmake --
#
#	The bundled libraries, pinned: release, download URL and SHA-256. The
#	backends declare them with FetchContent; cmake/Fetch.cmake downloads
#	them ahead of time for offline builds (TLS_SOURCES).

set(TLS_WOLFSSL_VERSION 5.9.4)
set(TLS_WOLFSSL_URL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.4-stable.tar.gz)
set(TLS_WOLFSSL_SHA256 7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57)

set(TLS_MBEDTLS_VERSION 3.6.7)
set(TLS_MBEDTLS_URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2)
set(TLS_MBEDTLS_SHA256 a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6)

set(TLS_OPENSSL_VERSION 3.5.9)
set(TLS_OPENSSL_URL https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz)
set(TLS_OPENSSL_SHA256 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a)

# The rustls crates are pinned by rustls/Cargo.lock.

# tls_fetch(lib): makes lib's pinned sources available as ${lib}_SOURCE_DIR,
# downloaded, or from TLS_SOURCES (see Fetch.cmake) when that is set.
macro(tls_fetch lib)
    string(TOUPPER ${lib} _L)
    if(TLS_SOURCES)
	set(_dir ${TLS_SOURCES}/${lib}-${TLS_${_L}_VERSION})
	if(NOT EXISTS ${_dir})
	    message(FATAL_ERROR "${_dir} is missing; fetch it with "
		"cmake -DDIR=${TLS_SOURCES} -P ${PROJECT_SOURCE_DIR}/cmake/Fetch.cmake")
	endif()
	set(FETCHCONTENT_SOURCE_DIR_${_L} ${_dir})
    endif()
    FetchContent_Declare(${lib} URL ${TLS_${_L}_URL}
	URL_HASH SHA256=${TLS_${_L}_SHA256}
	SOURCE_SUBDIR none)		# sources only, not its own build
    FetchContent_MakeAvailable(${lib})
endmacro()
