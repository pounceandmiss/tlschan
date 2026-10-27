/*
 * user_settings.h --
 *
 *	wolfSSL build configuration for tlschan::wolfssl: TLS 1.2/1.3 client and server,
 *	AEAD suites only, no OpenSSL compatibility layer.
 */

#ifndef TLS_WOLFSSL_USER_SETTINGS_H
#define TLS_WOLFSSL_USER_SETTINGS_H

/* Platform. Threads come from pthreads or Win32, picked by wolfSSL. */
#define WOLFSSL_USER_IO			/* all transport goes through tlsb_io */
#define WOLFSSL_IGNORE_FILE_WARN
#define HAVE_HASHDRBG
#ifndef _WIN32
#define HAVE_SYS_TIME_H
#define HAVE_GMTIME_R			/* Windows' gmtime is thread-local */
#endif
#ifdef __SIZEOF_INT128__
#define HAVE___UINT128_T
#endif
#if defined(__linux__) && !defined(__ANDROID__)
#define WOLFSSL_GETRANDOM
#endif
#if defined(__APPLE__) && !defined(WOLFSSL_APPLE_NATIVE_CERT_VALIDATION)
#define HAVE_SECURITY_SECTRUSTSETTINGS_H	/* macOS; link Security.framework */
#endif

/* Protocol. */
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define WOLFSSL_AEAD_ONLY		/* no CBC/stream suites */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_SESSION_TICKET		/* keys per conf, see TicketCb */
#define WOLFSSL_TICKET_NONCE_MALLOC	/* peers such as rustls use 32 byte nonces */
/* Session objects for client resumption (per conf, see CachePut); the
 * process-wide tables stay minimal and every context turns them off. */
#define MICRO_SESSION_CACHE
#define NO_CLIENT_CACHE
#define NO_SESSION_CACHE_REF
#define HAVE_KEYING_MATERIAL
#define HAVE_HKDF
#define NO_PSK

/* Certificates. */
#define SESSION_CERTS			/* full peer chain after the handshake */
#define WOLFSSL_ALWAYS_VERIFY_CB	/* verify callback on success too ... */
#define WOLFSSL_VERIFY_CB_ALL_CERTS	/* ... and for every chain cert */
#define WOLFSSL_ALT_CERT_CHAINS		/* only the leaf must reach a trust anchor */
#define WOLFSSL_IP_ALT_NAME		/* IP SANs for IP literal servernames */
#define WOLFSSL_SYS_CA_CERTS
#define WOLFSSL_ENCRYPTED_KEYS
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_ASN_TEMPLATE

/* Public key. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_SP_4096			/* RSA-4096 roots are common */
#define SP_INT_BITS 4096
#define WOLFSSL_HAVE_SP_ECC
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define ECC_SHAMIR
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define NO_DH
#define NO_DSA

/* Symmetric and hashes. */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define HAVE_AES_CBC			/* encrypted keys; AEAD_ONLY keeps it out of TLS */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define NO_OLD_POLY1305			/* pre-RFC 7905 ChaCha suites */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_DES3
#define NO_RC4
#define NO_MD4				/* MD5 stays: legacy encrypted PEM keys */

#endif /* TLS_WOLFSSL_USER_SETTINGS_H */
