/*
 * config.h --
 *
 *	MBEDTLS_USER_CONFIG_FILE for the bundled Mbed TLS: the default
 *	configuration, made thread safe where pthreads exist. Without it the
 *	backend serializes all Mbed TLS calls behind one lock.
 */

#if !defined(_WIN32)
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
#endif
