# tlschan

TLS for Tcl 9 channels, as four backend packages that share one channel
layer, and `tlschan`, which loads whichever of them is available:

| package            | backend      | library used                              | crypto            |
|--------------------|--------------|-------------------------------------------|-------------------|
| `tlschan::wolfssl` | wolfSSL      | bundled 5.9.4 by default, or the system's | wolfCrypt         |
| `tlschan::rustls`  | rustls 0.23  | always compiled in (cargo)                | ring              |
| `tlschan::mbedtls` | Mbed TLS 3.6 | the system's or bundled 3.6.7             | Mbed TLS / PSA    |
| `tlschan::openssl` | OpenSSL 3    | the system's or bundled 3.5 LTS           | OpenSSL libcrypto |

Every package builds as a loadable module or as a static archive for
embedding, whichever library it uses (see Building).

All are drop-in replacements for [tcltls](https://core.tcl-lang.org/tcltls)
and [tclmtls](https://github.com/chpock/tclmtls): the same commands and
options. Package names never clash with tcltls's `tls`.

```tcl
package require tlschan
package require http
http::register https 443 ::tlschan::socket
http::geturl https://www.tcl-lang.org/
```

`tlschan` takes the first backend of `::tlschan::prefer` (set before
loading: `namespace eval tlschan {variable prefer {mbedtls openssl}}`),
else of `$env(TLSCHAN_BACKEND)`, else of `openssl rustls mbedtls wolfssl`,
that is already loaded or loads; `tlschan::backend` names it. If none
does: `no TLS backend available (tried ...)`, errorCode `TLS BACKEND`. Its
commands become `::tlschan::*` aliases, and `::tls::*` too unless
`::tls::socket` exists already, so tcltls code runs unchanged (a tcltls
loaded later takes them over). `package require tlschan::openssl` pins a
backend; a backend by itself never touches `::tls`.

## Reference

[`doc/tlschan.md`](doc/tlschan.md) is the reference: every command,
option, callback and error, and how the backends differ. The same page is
`man tlschan` once installed, `doc/tlschan.html`, and `man -l
doc/tlschan.n` in the tree; all are generated from `doc/tlschan.man`.

In short, the commands are tcltls's (`socket`, `import`/`starttls`,
`unimport`/`unstack`, `handshake`, `status`, `connection`, `init`,
`ciphers`, `protocols`, `version`) plus `exporter` and tclmtls's crypto
helpers, in `::tlschan` and in each backend's namespace. Clients verify the
peer against the system trust store by default, TLS 1.2 and 1.3 only.

## Building

Needs CMake 3.24 or later, a C compiler and a Tcl 9 build. `tlschan::rustls`
also needs cargo, and a bundled OpenSSL needs perl. Bundled libraries are pinned
releases, downloaded and checked against their SHA-256 at configure time.

```sh
cmake -B build                 # TCL_CONFIG=.../tclConfig.sh if not found
cmake --build build
ctest --test-dir build         # -DTLS_TEST_NETWORK=ON adds Internet tests
cmake --install build          # into Tcl's prefix unless told otherwise
```

| option                                      |                                                                                                                             |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `TCL_CONFIG`                                | `tclConfig.sh` of the Tcl 9 to build against                                                                                |
| `TLS_BACKENDS`                              | backends to build: some of `wolfssl rustls mbedtls openssl`, or `all`; empty (the default) builds one over a system library |
| `BUILD_SHARED_LIBS`                         | `ON`: loadable modules; `OFF`: static archives                                                                              |
| `TLS_WOLFSSL`, `TLS_MBEDTLS`, `TLS_OPENSSL` | `AUTO`, `SYSTEM` or `BUNDLED`                                                                                               |
| `TLS_RUST_TARGET`                           | Rust target of a cross build, if not derived                                                                                |
| `TLS_SANITIZE`                              | e.g. `address,undefined`, for everything                                                                                    |

By default only one backend is built, over a TLS library the system
maintains: `tlschan::openssl` if OpenSSL 3 is installed, else
`tlschan::mbedtls` over Mbed TLS 3.6, else configure stops and says so.
Nothing is downloaded or compiled in unless asked for: name backends in
`TLS_BACKENDS` (`-DTLS_BACKENDS=wolfssl`, `-DTLS_BACKENDS=all`) or bundle a
library as below. `package require tlschan` works whichever were built.

### System or bundled libraries

Each of wolfSSL, Mbed TLS and OpenSSL comes either from the system or as a
pinned release compiled into the package, chosen per library with
`TLS_WOLFSSL`, `TLS_MBEDTLS` or `TLS_OPENSSL`:

| value     | meaning                                                         |
|-----------|-----------------------------------------------------------------|
| `AUTO`    | modules: the installed OpenSSL 3 or Mbed TLS 3.6, else bundled  |
|           | static builds, and wolfSSL always: bundled                      |
| `SYSTEM`  | the installed library; configure fails if none is found         |
| `BUNDLED` | download, check and compile the pinned release into the package |

```sh
cmake -B build -DTLS_OPENSSL=BUNDLED          # OpenSSL compiled in
cmake -B build -DTLS_MBEDTLS=SYSTEM \
    -DCMAKE_PREFIX_PATH=/opt/mbedtls          # a particular Mbed TLS install
cmake -B build -DTLS_WOLFSSL=SYSTEM           # distribution wolfSSL
```

A system library is found the usual CMake way: `CMAKE_PREFIX_PATH` for
any of them, or `OPENSSL_ROOT_DIR`, `MbedTLS_DIR`, and `wolfssl_DIR` or
`PKG_CONFIG_PATH` for wolfSSL. Distribution builds of wolfSSL usually lack
ALPN, the exporter, IP address checks, encrypted keys or chain access;
configure lists what is missing. rustls has no system library: cargo
always compiles it in.

### Offline builds

Bundled libraries are downloaded at configure time, and rustls's crates by
cargo at build time. To build without network access, fetch them once
into a directory, then point the build at it:

```sh
cmake -DDIR=/path/to/sources -P cmake/Fetch.cmake     # online, once
cmake -B build -DTLS_SOURCES=/path/to/sources ...     # offline from here
```

`Fetch.cmake` downloads the pinned wolfSSL, Mbed TLS and OpenSSL releases
(checking each SHA-256, pins in `cmake/Sources.cmake`) into
`<name>-<version>` directories, and vendors the crates of
`rustls/Cargo.lock` into `cargo/` if cargo is installed. With
`TLS_SOURCES` set nothing is downloaded; a missing directory stops
configure with the command that fetches it. A build that bundles nothing
(the default) needs no network either way.

Modules go to `lib/tlschan_<backend>0.1.0/libtcl9tlschan_<backend>0.1.0.so`
(Windows `tcl9tlschan_<backend>010.dll`), `tlschan` to `lib/tlschan0.1.0/`
(static builds too), each with its `pkgIndex.tcl`. A module exports only
its init function, whatever it links in.

### Static archives

`BUILD_SHARED_LIBS=OFF` gives `lib/libtcl9tlschan_<backend>0.1.0.a`: one
relocatable object whose only global symbol is `Tlschan_<backend>_Init`, so
several packages, and other copies of the same TLS libraries, can share a
program. A bundled library is folded in; a `SYSTEM` one is not, and
`lib/pkgconfig/tcl9tlschan_<backend>.pc` names it along with the OS libraries.
Link it with Tcl's stub library (`libtclstub.a`), register it with
`Tcl_StaticLibrary(NULL, "Tlschan_wolfssl", Tlschan_wolfssl_Init, NULL)`
(NULL: with an interp it counts as already loaded there) and
`package ifneeded tlschan::wolfssl 0.1.0 {load {} Tlschan_wolfssl}`, and
ship `lib/tlschan0.1.0/` in the script library next to them for
`package require tlschan`. ctest runs the suite through a tclsh with all of
them linked in. With MSVC the archive is a plain one.

For zippy, against its shared Mbed TLS: it links
`libtcl9tlschan_mbedtls0.1.0.a`, registers `Tlschan_mbedtls` as
`tlschan::mbedtls` and ships `tlschan.tcl`:

```sh
cmake -B build -DBUILD_SHARED_LIBS=OFF -DTLS_BACKENDS=mbedtls \
    -DTLS_MBEDTLS=SYSTEM -DCMAKE_PREFIX_PATH=$PREFIX \
    -DTCL_CONFIG=$PREFIX/lib/tclConfig.sh
cmake --build build && cmake --install build --prefix $PREFIX
```

### Windows

MinGW-w64, cross from Linux, with the tests under wine:

```sh
cmake -B build-win --toolchain cmake/mingw-w64.cmake \
    -DTCL_CONFIG=<MinGW Tcl 9>/lib/tclConfig.sh
```

The DLLs depend on system DLLs only. `tlschan::rustls` needs the
`x86_64-pc-windows-gnu` Rust target. Windows ships few root certificates
and downloads the rest when CryptoAPI builds a chain, so with the system
store chains are also built by CryptoAPI: it decides for `tlschan::mbedtls`,
and supplies the missing root and intermediates to the other backends. MSVC builds should work but are
untested.

### Backend notes

Mbed TLS is compiled with its default configuration plus
`mbedtls/config.h` (thread safety); an installed one without
`MBEDTLS_THREADING_C` gets all calls serialized behind one lock. Its system
trust store and Windows chain verification come from
[tclmtls](https://github.com/chpock/tclmtls), Copyright (c) Konstantin
Kushnir, under its license (`mbedtls/license.terms`).

Without `-cafile`/`-cadir` `tlschan::openssl` trusts OpenSSL's default paths
(plus the usual bundles, and the Windows store with OpenSSL 3.2+); `-cadir`
is an OpenSSL hashed directory (`openssl rehash`).

## License

Tcl's BSD-style license; see `license.terms`.
