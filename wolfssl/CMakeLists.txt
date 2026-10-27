# tlschan::wolfssl: wolfSSL. Distribution builds of wolfSSL usually lack features the
# package uses, so AUTO means BUNDLED here; SYSTEM says what is missing.

set(TLS_WOLFSSL AUTO CACHE STRING "wolfSSL: AUTO (= BUNDLED), BUNDLED or SYSTEM")
set_property(CACHE TLS_WOLFSSL PROPERTY STRINGS AUTO BUNDLED SYSTEM)

add_library(wolfssl_backend OBJECT backend.c)
target_include_directories(wolfssl_backend PUBLIC ${PROJECT_SOURCE_DIR}/generic)
tls_warnings(wolfssl_backend)

if(TLS_WOLFSSL STREQUAL "SYSTEM")
    find_package(wolfssl CONFIG)
    if(wolfssl_FOUND)
	set(wolfssl wolfssl::wolfssl)
    else()
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(wolfssl REQUIRED IMPORTED_TARGET GLOBAL wolfssl)
	set(wolfssl PkgConfig::wolfssl)
    endif()
    include(CheckSymbolExists)
    set(CMAKE_REQUIRED_LIBRARIES ${wolfssl})
    set(missing)
    foreach(feature HAVE_ALPN HAVE_KEYING_MATERIAL SESSION_CERTS
	    WOLFSSL_ENCRYPTED_KEYS HAVE_SNI WOLFSSL_TLS13)
	check_symbol_exists(${feature} wolfssl/options.h WOLFSSL_${feature})
	if(NOT WOLFSSL_${feature})
	    list(APPEND missing ${feature})
	endif()
    endforeach()
    if(missing)
	message(WARNING "System wolfSSL lacks ${missing}: tlschan::wolfssl loses the "
	    "matching features (TLS_WOLFSSL=BUNDLED has them all)")
    endif()
    target_link_libraries(wolfssl_backend PUBLIC ${wolfssl})
    tls_package(wolfssl OBJECTS wolfssl_backend
	LIBS ${wolfssl} ${TLS_OS_LIBS} REQUIRES wolfssl)
    return()
endif()

tls_fetch(wolfssl)

set(tls internal keys ssl tls tls13 wolfio)
set(crypt aes asn chacha chacha20_poly1305 coding cpuid curve25519 ecc
    ed25519 error fe_operations ge_operations hash hmac kdf logging md5
    memory poly1305 pwdbased random rsa sha sha256 sha512 signature sp_c32
    sp_c64 sp_int wc_encrypt wc_port wolfmath)
list(TRANSFORM tls PREPEND ${wolfssl_SOURCE_DIR}/src/)
list(TRANSFORM tls APPEND .c)
list(TRANSFORM crypt PREPEND ${wolfssl_SOURCE_DIR}/wolfcrypt/src/)
list(TRANSFORM crypt APPEND .c)

add_library(wolfssl_bundled OBJECT ${tls} ${crypt})
target_compile_definitions(wolfssl_bundled PUBLIC WOLFSSL_USER_SETTINGS)
target_include_directories(wolfssl_bundled PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} ${wolfssl_SOURCE_DIR})
set_source_files_properties(${tls} ${crypt} PROPERTIES
    OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/user_settings.h)
target_link_libraries(wolfssl_backend PUBLIC wolfssl_bundled)

tls_package(wolfssl
    OBJECTS wolfssl_backend wolfssl_bundled LIBS ${TLS_OS_LIBS})
