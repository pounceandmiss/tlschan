# Writing a TLS backend

A backend implements `generic/tlsb.h` on top of one TLS library and knows
nothing about Tcl. Everything else in `generic/` is shared by every
package: the stacked channel driver `tlsIO.c` (its header comment explains
watch masks, the ciphertext queue, held EOFs and `TLS_BUSY`) with its
internals in `tlsInt.h`; the commands in `tls.c` and `tls.tcl`;
certificate decoding in `x509.c`; Windows chain building in `winroot.c`;
and the umbrella package in `tlschan.tcl`.

| Directory | Package            | Library  | Language |
|-----------|--------------------|----------|----------|
| `wolfssl` | `tlschan::wolfssl` | wolfSSL  | C        |
| `rustls`  | `tlschan::rustls`  | rustls   | Rust     |
| `mbedtls` | `tlschan::mbedtls` | Mbed TLS | C        |
| `openssl` | `tlschan::openssl` | OpenSSL  | C        |

All four behave the same at the Tcl level except where this guide says
otherwise.

## 1. Layering

| The layer owns                                                                                        | The backend owns                                                 |
|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| Reading `-cafile`, `-certfile`, `-keyfile`; the backend gets bytes, never paths, except `cadir`       | Parsing PEM/DER certificates and keys, decrypting keys           |
| Running `-password` (a script) and passing its result as a string                                     | Trust store setup, system store loading                          |
| Option names, defaults and booleans; `-model` sharing and anchors                                     | Cipher name lookup and protocol limits                           |
| Checking a client's `-servername` (host name or IP literal) and ALPN names (1 to 255 bytes)           | ALPN negotiation, SNI, name verification                         |
| Tcl events, watch masks, timers, blocking and nonblocking mode                                        | The TLS state machine, which never blocks                        |
| Queueing ciphertext the socket refuses                                                                | Producing ciphertext through `send`, consuming it through `recv` |
| `-command` and `-validatecommand` scripts, bgerror                                                    | Calling `io->verify` with a verdict per certificate              |
| Tcl results, `errorCode` (`TLS CONFIG`, `TLS MODEL`, `TLS IMPORT`, `TLS HANDSHAKE`, ...), POSIX codes | One message per failure, in `tlsb_errmsg` or the `err` buffer    |
| The `handshake failed: ` prefix                                                                       | Messages without that prefix                                     |
| Decoding certificates for `status` and the verify callback (`x509.c`)                                 | Giving out certificates as DER                                   |
|                                                                                                       | Session tickets and the client session cache (section 5)         |

## 2. Lifecycle and call order

```
tlsb_global_init                     on each package load (each interp, any thread)
tlsb_conf_new(opts)                  once per configuration (see below)
  tlsb_sess_new(conf, name, io)      once per channel
    tlsb_handshake ...               until TLSB_OK or TLSB_ERROR
    tlsb_read / tlsb_write ...       only once the handshake is done
    tlsb_info_get, tlsb_peer_cert(0), tlsb_local_cert, tlsb_export
    tlsb_close_notify                on close, only if the session is open
  tlsb_sess_free
tlsb_conf_free                       when the last user of it is gone
```

- **`tlsb_global_init`** runs on every package load, possibly in several
  threads at once: guard it with a once primitive and make repeat calls
  cheap. A failure becomes `TLS INIT`. `tlsb_version`, `tlsb_protocols` and
  `tlsb_ciphers` must work without it.
- **Confs** come from `ConfNew` in `tls.c`: one per import, unless `-model`
  names a channel. A TLS channel lends its conf; any other channel anchors
  one, created by the first import and released when that channel closes.
  `socket -server` anchors on its listening socket, so **one server conf
  serves every accepted connection**, possibly on several threads
  (section 8). A model of the other side (client vs server) is refused
  with `TLS MODEL`.
- **Lifetimes:** confs are refcounted and a session is always freed before
  its conf. `tlsb_opts` and everything it points to are freed when
  `tlsb_conf_new` returns, and `io` points to a stack variable: **copy what
  you keep** (blobs, password, cipher and ALPN strings, the `tlsb_io`
  struct, `servername`).
- **Sessions:** a failure becomes `TLS IMPORT`. Server sessions also get
  `-servername` (unchecked); ignore it.
- **The handshake** is driven by `TlsHandshake`, from the event handler in
  nonblocking mode and from reads, writes and the `handshake` command.
  After `TLSB_OK`, later calls must keep returning `TLSB_OK`.
- **Read, write, info, certificates and export** are called only while the
  channel is open; the layer asks `tlsb_peer_cert` for depth 0 only, and
  `tlsb_export` for 1 to 8160 bytes.
- **`tlsb_close_notify`** comes on a full close or a write half-close of an
  open channel; the session stays usable for reads after a half-close.
- **After a failure** the only later call is `tlsb_sess_free`.

### What can run inside a callback

- `recv` and `send` only touch the channel below; they never call back into
  the backend.
- `verify` runs the `-validatecommand` script synchronously inside
  `tlsb_handshake`. The script may open other TLS channels (other sessions,
  possibly of the same conf), and the layer calls `tlsb_digest` there.
  **Never hold a lock across `recv`, `send` or `verify`.**
- The same session is never re-entered: while a backend call runs
  (`TLS_BUSY`), the layer answers "would block" itself.
- `-command` callbacks run only after the backend call returns.

## 3. The I/O contract

### `tlsb_io.recv(ud, buf, len)`

| Return | Meaning                                                                                                                  |
|--------|--------------------------------------------------------------------------------------------------------------------------|
| `> 0`  | That many bytes of ciphertext                                                                                            |
| `0`    | Nothing available now (would block); the layer sets `TLS_STARVED`                                                        |
| `-1`   | EOF or an error below, indistinguishably. On an error the layer saves the errno, which replaces your message (section 6) |

`recv` first flushes queued ciphertext (the peer may be waiting for your
ClientHello). In blocking mode it returns `> 0` or `-1`.

**Return `TLSB_WANT_READ` only after `recv` returned `0` in this call.**
The layer then waits for the socket to become readable. Libraries also
report would-block after consuming a record that yields nothing (a ticket,
a KeyUpdate, part of a flight): then call the library again. The C
backends track this with a `dry` flag set in their recv callback; rustls
loops in `pump`. Never loop on `recv` waiting for data, and latch EOF.

### `tlsb_io.send(ud, buf, len)`

`send` takes all of `buf` and never fails; the layer queues what the socket
refuses, and transport errors surface later as layer failures. It may be
called from any session call, `tlsb_read` included (KeyUpdate replies,
tickets).

### Return values

| Call             | Returns                                                                                                                   |
|------------------|---------------------------------------------------------------------------------------------------------------------------|
| `tlsb_handshake` | `TLSB_OK`, `TLSB_WANT_READ` or `TLSB_ERROR`                                                                               |
| `tlsb_read`      | bytes `> 0`; `0` on EOF (close_notify **or** transport EOF, including a truncated record); `TLSB_WANT_READ`; `TLSB_ERROR` |
| `tlsb_write`     | `len` (always all of it) or `TLSB_ERROR`; loop internally over record or `INT_MAX` limits                                 |

- **EOF during the handshake** is an error: `connection closed during
  handshake`.
- **After EOF** `tlsb_read` keeps returning `0`.
- **Errors are sticky**: later calls must not crash, and the message must
  survive `tlsb_info_get` and `tlsb_peer_cert` calls (the layer may hold an
  error and read `tlsb_errmsg` later).
- **A TLS 1.3 client** finishes its handshake before the server has judged
  its certificate; a rejection arrives through `tlsb_read`.

### `tlsb_pending`

Nonzero if `tlsb_read` might make progress without new ciphertext.
Decrypted data inside the backend raises no socket event, so while it is
pending the layer schedules reads with a timer until `recv` returns `0`. A
pending partial record is fine, provided the following `tlsb_read` calls
`recv` before returning `TLSB_WANT_READ`; otherwise the layer busy-loops
(io-6.1 to io-6.3 measure CPU time). It is called often: keep it cheap and
do no I/O.

## 4. Verification

### `io->verify(ud, depth, der, len, ok, err)`

Set only when `-validatecommand` is given. It returns the script's
verdict (an error counts as reject); nonzero accepts. All backends follow
these rules:

- Call it for each certificate the **peer sent**, from the highest depth
  down to 0, with your verdict: `ok`, and `err` (the reason, or NULL when
  `ok`).
- Trust anchors from your store that the peer did not send are not
  reported; their errors carry over to the certificate below.
- Each depth gets its own verdict. Every certificate below a bad one gets
  `ok=0` with `issuer certificate not trusted`.
- A nonzero return for a bad certificate means: carry on as if it were
  good.
- Stop at the first certificate the callback rejects; the handshake fails
  with `certificate rejected by validation callback`.
- Example (harness TestExpired, io-7.3): with an expired intermediate and a
  valid leaf the callback sees `[certificate has expired]` at depth 1 and
  `[issuer certificate not trusted]` at depth 0.
- Accepting a bad certificate must not leak into the shared conf (wolfSSL
  caches accepted CAs; its backend guards against that).
- Sessions with `verify` are never resumed (section 5).

**rustls** gets one webpki verdict per chain and derives per-depth verdicts
itself (`rustls/src/chain.rs`): expiry and validity per certificate, an
unknown issuer or self-signed root at the top of the chain, a name mismatch
at depth 0. Limits: certificates after a break in the issuer links are not
reported; other failures (signature, purpose, constraints) are blamed on
the leaf; whether the top certificate is anchored is judged by subject name
and key.

### Policy

| Side                                     | No callback                                                       | With callback                                             |
|------------------------------------------|-------------------------------------------------------------------|-----------------------------------------------------------|
| Client, `require=1` (default)            | Verify; a bad verdict fails the handshake                         | The callback's return decides                             |
| Client, `require=0`                      | Accept everything (wolfSSL and rustls skip verification entirely) | Verify anyway, so the callback gets a real verdict        |
| Server, `request=0, require=0` (default) | No CertificateRequest                                             | Not called                                                |
| Server, `request=1`                      | Ask; verify a certificate if sent; accept failures                | The callback's return decides                             |
| Server, `require=1`                      | Ask; fail with no certificate or a bad one                        | The callback's return decides; no certificate still fails |

### Names

`servername` (client only) is both the SNI and the name to verify; the
layer has checked that it is a host name or an IP literal.

- `NULL`: no SNI; verify the chain without a name check.
- IPv4 or IPv6 literal: **no SNI**; match against IP SANs only.
  `127.0.0.1` passes against the test certificate; `127.0.0.2` and `::1`
  fail with `hostname mismatch`.
- Otherwise a DNS name: send SNI and check DNS SANs. OpenSSL also sets
  `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`.

`socket` passes the host as `-servername` by default, and the tests
connect to `127.0.0.1`, so IP literals are common.

### Trust

- `ca` (bytes) and `cadir` (a path) add to an explicit store.
- With neither, trust the **system store**, loaded lazily and thread-safely
  (once per process in OpenSSL, Mbed TLS and rustls; per conf, under the
  conf lock, in wolfSSL). Clients load it; servers only when they ask for
  client certificates (`request` or `require`).
- OpenSSL sets `X509_V_FLAG_PARTIAL_CHAIN`, so any certificate in `ca`
  anchors a chain.
- What the system store and `cadir` mean is up to the library; the man
  page (BACKEND DIFFERENCES) says what each backend does.
- Windows fetches most roots only on demand, so its ROOT store is mostly
  empty. When the system store has no issuer for a peer chain, call
  `tlsb_win_chain` (`generic/winroot.c`, `_WIN32` only): CryptoAPI builds
  the chain and hands back its root, to trust, and any intermediates the
  peer did not send, to use for that chain only. (Mbed TLS instead leaves
  the whole verdict to CryptoAPI there, as tclmtls does.)

### Messages

All four use these reasons, after OpenSSL's
`X509_verify_cert_error_string`. The handshake error is
`certificate verify failed: <reason>`, with the reason of the topmost
failing depth; the callback gets the bare reason.

| Situation                 | Reason                                                    |
|---------------------------|-----------------------------------------------------------|
| Name mismatch (DNS or IP) | `hostname mismatch`                                       |
| Expired, not yet valid    | `certificate has expired`, `certificate is not yet valid` |
| Unknown issuer            | `unable to get local issuer certificate`                  |
| Self-signed, untrusted    | `self-signed certificate`                                 |
| Below a bad certificate   | `issuer certificate not trusted`                          |
| Anything else             | the library's words                                       |

Other handshake messages: `certificate rejected by validation callback`
(the callback returned 0) and `peer did not return a certificate` (a server
requiring one got none). Mbed TLS maps its flag bits to these strings
(`FlagStr`), wolfSSL its error codes (`ErrStr`), rustls its error variants
(`cert_reason` in `rustls/src/errors.rs`).

## 5. Options and sessions

`ConfNew` in `tls.c` fills `tlsb_opts`:

| Field                     | From                                                                        | Notes                                                                                                                                                                                            |
|---------------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `server`                  | `-server`                                                                   |                                                                                                                                                                                                  |
| `request`, `require`      | `-request`, `-require`; default `!server`                                   | The layer sets `request \|= require`; the backends OR them again                                                                                                                                 |
| `protocols`               | `tlsb_protocols() & (-tls1.2, -tls1.3)`                                     | Never 0 from the layer, which raises `no protocols enabled` (`TLS PROTOCOL`) first. **Treat 0 as "all"**: the harnesses pass 0. Bits you don't support → `no supported protocol version enabled` |
| `ca`, `ca_len`            | contents of `-cafile`                                                       | There is no inline CA option                                                                                                                                                                     |
| `cadir`                   | `-cadir`                                                                    | A path; the backend reads it                                                                                                                                                                     |
| `cert`, `cert_len`        | `-cert` (bytes) or the contents of `-certfile`                              | Inline wins when nonempty                                                                                                                                                                        |
| `key`, `key_len`          | `-key`, or `-keyfile`, **or `-certfile` again** when there is no `-keyfile` | So a key blob may hold certificates and a cert blob may hold a key: skip PEM blocks of other types                                                                                               |
| `password`                | result of the `-password` script (`return value` counts)                    | Run only when a key is given                                                                                                                                                                     |
| `ciphers`, `ciphersuites` | `-cipher`, `-ciphersuites`                                                  | NULL when empty                                                                                                                                                                                  |
| `alpn`, `alpn_count`      | `-alpn` list                                                                | Each 1 to 255 bytes, checked by the layer                                                                                                                                                        |

Empty `-command`, `-validatecommand` and `-vcmd` count as not given.

### Blobs and configuration errors

- A blob of length 0 counts as absent.
- PEM is recognised by `-----BEGIN`; anything else is a single DER object.
- `cert` is a PEM chain (leaf first; the rest is sent as the chain) or one
  DER certificate.
- `key` is PEM (PKCS#8, traditional, or `ENCRYPTED PRIVATE KEY`) or DER
  PKCS#8. OpenSSL and wolfSSL also decrypt encrypted DER. The test keys are
  P-256 ECDSA PKCS#8; `server-key-enc.pem` is PBES2 with AES-256-CBC and
  password `secret`; the self-signed key is RSA-2048.
- `cert` and `key` go together. A server needs both.

`tlsb_conf_new` writes its error to `err` (NUL terminated, truncated to
`errlen`); it becomes `TLS CONFIG`. Messages marked exact are the same in
all four and checked by conf.test:

| Case                       | Message                                                   |
|----------------------------|-----------------------------------------------------------|
| Wrong password             | `wrong password` (exact)                                  |
| Encrypted key, no password | `password required` (exact)                               |
| Server without credentials | `server requires a certificate and key` (exact)           |
| Key does not match         | `private key does not match certificate` (exact)          |
| Bad cadir                  | `cannot read cadir: <path>` (exact)                       |
| Bad cipher name            | `unknown cipher: <name>` (exact)                          |
| No suites left             | `no usable cipher suites` (exact)                         |
| Bad ALPN entry             | `invalid ALPN protocol name` (the layer catches it first) |
| Bad certificate            | `cannot parse certificate`                                |
| Bad key                    | `cannot parse private key`                                |
| Only one of cert and key   | `certificate and private key go together`                 |
| Bad CA blob                | `cannot parse CA certificates`                            |

### Ciphers

- Separators: any of `: ,\t\r\n`; empty tokens are ignored.
- Names, case-insensitive: IANA (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`),
  IANA with `-` for `_`, OpenSSL (`ECDHE-ECDSA-AES128-GCM-SHA256`) and the
  library's own.
- Names of either protocol may appear in either option. Sort each name to
  its protocol; the names a protocol receives replace its defaults. A
  protocol that receives none keeps its defaults, unless its own option
  (`ciphers` for TLS 1.2, `ciphersuites` for TLS 1.3) was given: then it is
  disabled. If no protocol remains: `no usable cipher suites`. A TLS 1.2
  name in `ciphersuites` must never make a handshake fail.
- `tlsb_ciphers(protocols, cb, ud)` calls `cb` once per suite: IANA names,
  certificate-based suites only (no PSK or ECJPAKE), only the requested
  protocols, no duplicates. Tests require `TLS_AES_128_GCM_SHA256` in the
  TLS 1.3 list and not the TLS 1.2 list,
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` in the TLS 1.2 list, and the
  negotiated `tlsb_info.cipher` in the full list.

### ALPN

- The client offers the list in order; the server picks by its own
  preference (wolfSSL picks by the client's).
- No overlap means no ALPN on either end, not a failure, and a client never
  fails because the server chose nothing (io-7.7). OpenSSL returns `NOACK`,
  wolfSSL uses `CONTINUE_ON_MISMATCH`, rustls goes through its `Acceptor`
  and picks a conf without ALPN, Mbed TLS peeks at the ClientHello and
  binds the session to a second configuration without ALPN.
- io-1.8: server `{h2 http/1.1}`, client `{foo http/1.1}`; both ends report
  `http/1.1`.

### Session resumption

The Tcl level has no session options: resumption follows from conf sharing
(section 2). Every backend implements it alike, for TLS 1.2 and TLS 1.3:

- **Server:** issue session tickets under a key that belongs to the conf,
  so all sessions of one conf, and only those, resume each other's tickets.
  Do not resume, and preferably do not issue tickets, for a session with
  `io->verify`.
- **Client:** the conf keeps the most recent session per servername (at
  most 32 servernames, oldest dropped) and offers it to the next session
  with the same servername. Store it once it is resumable (TLS 1.3: after a
  NewSessionTicket, which arrives during a `tlsb_read`). Do not cache or
  offer for a session without servername or with `io->verify`.
- Lock the cache briefly: it is shared across threads (section 8).
- Keep process-wide library caches off, so nothing resumes across confs.
- `tlsb_info.resumed` reports an abbreviated handshake.

### `tlsb_info` and certificates

`tlsb_info_get` is valid after the handshake, else `TLSB_ERROR`. Its
pointers, and the DER from `tlsb_peer_cert` and `tlsb_local_cert`, must
stay valid as long as the session.

| Field              | Content                                                                                                                                                |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `protocol`         | `"TLS1.2"` or `"TLS1.3"`; the layer reports `"TLSv" + protocol+3`                                                                                      |
| `cipher`           | The IANA name, as `tlsb_ciphers` gives it                                                                                                              |
| `cipher_bits`      | Symmetric key bits, 128 or 256 (ChaCha20 is 256)                                                                                                       |
| `alpn`, `alpn_len` | Bytes without a NUL; NULL if none                                                                                                                      |
| `servername`       | Server: the SNI received, or NULL. Client: the SNI sent, so NULL for an IP literal or no name. The layer falls back to its own `-servername` when NULL |
| `resumed`          | Nonzero for an abbreviated handshake                                                                                                                   |

- `tlsb_peer_cert(depth)`: depth 0 is the peer's leaf; a missing one
  returns `TLSB_ERROR`.
- `tlsb_local_cert` returns your leaf as DER (for `status -local`), or
  `TLSB_ERROR` without a certificate.
- `tlsb_export` implements RFC 5705 / RFC 8446 §7.5. The label is not NUL
  terminated (use `label_len`). `use_ctx` distinguishes no context from an
  empty one; the two give different output, and both ends must agree. On
  failure the layer reports `keying material export failed` (`TLS EXPORT`)
  itself.
- `tlsb_version` returns `"<Library> <x.y...>"`, for example
  `"wolfSSL 5.9.4"` or `"Mbed TLS 3.6.7"`. basic-2.4 matches
  `^(wolfSSL|rustls|Mbed TLS|OpenSSL) [0-9]+\.[0-9]+`.
- `tlsb_protocols` returns the bits the build supports; basic-2.1 expects
  both.

## 6. Errors

`TLSB_ERROR` means "read `tlsb_errmsg(s)`". The layer makes that message
the channel error (`ECONNABORTED`), passes it to `-command error`, and adds
the `handshake failed: ` prefix during the handshake. Pick the message in
this order:

1. A recorded verification failure (`verr`), unprefixed.
2. Transport EOF: `connection closed during handshake` before the handshake
   is done, `connection closed` after.
3. A fatal alert received: `peer sent alert: <name>`, unprefixed, with
   lowercase RFC alert names such as `handshake failure`,
   `certificate required` or `unknown CA`. Mbed TLS 3.6 does not say which
   alert it received, so its backend reports `peer sent alert`.
4. Otherwise the library's reason, prefixed with `<what>`: nothing for
   `tlsb_handshake` (the layer names the handshake), `read failed: ` and
   `write failed: ` for read and write.

A write before the handshake fails with `handshake not complete`. With no
error recorded, return `unknown error`; never return an empty string.

If `recv` reported an I/O error (not EOF), the layer replaces your message
with the errno's text, so a refused `-async` connect reads
`handshake failed: connection refused`.

Which alert a server sends is up to the library; the man page lists the
differences.

## 7. Crypto helpers

All return `TLSB_OK` or `TLSB_ERROR`, must be thread-safe, and can be
called from inside a verify callback.

| Function                                                           | Contract                                                                                                                                                                |
|--------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tlsb_random(buf, len)`                                            | CSPRNG output. The layer asks for 1 byte to 1 MiB; the harness for 200000 bytes                                                                                         |
| `tlsb_digest(alg, data, len, out)`                                 | `TLSB_SHA1`, `TLSB_SHA256` or `TLSB_SHA512`: 20, 32 or 64 bytes into a 64-byte `out`. Any other `alg` → `TLSB_ERROR`                                                    |
| `tlsb_pbkdf2(alg, pw, pw_len, salt, salt_len, iter, out, out_len)` | PBKDF2-HMAC with that digest, binary-safe (NULs). `iter == 0` → `TLSB_ERROR`. The layer allows 1..10^7 iterations and lengths 1..64                                     |
| `tlsb_aes256gcm_seal(key, nonce, in, len, out)`                    | AES-256-GCM, 12-byte nonce, no AAD. `out` is the ciphertext (`len` bytes) followed by the 16-byte tag. `len` may be 0. Allow `in == out`                                |
| `tlsb_aes256gcm_open(key, nonce, in, len, out)`                    | `in` is ciphertext followed by the tag; `len < 16` → `TLSB_ERROR`. Writes `len - 16` bytes. Authentication failure → `TLSB_ERROR` (OpenSSL and wolfSSL then zero `out`) |

At the Tcl level `aesgcm-encrypt` returns `nonce(12) || ciphertext ||
tag(16)`, with the nonce from `tlsb_random`; `aesgcm-decrypt` splits it.

| Test vector                                            | Expected                               |
|--------------------------------------------------------|----------------------------------------|
| SHA-1, SHA-256, SHA-512 of `abc`                       | FIPS values                            |
| PBKDF2-SHA1                                            | RFC 6070                               |
| PBKDF2-SHA256 (`passwd`/`salt`, 1 iteration, 64 bytes) | RFC 7914 §11                           |
| GCM: zero key, zero nonce, empty input                 | tag `530f8afbc74536b9a963b4f1c4cb738b` |
| GCM: zero key, zero nonce, 16 zero bytes               | `cea7403d...d48ab919`                  |

## 8. Threads

- **A session is used by one thread at a time**, the one owning the
  channel. Channels can move to another thread (`TlsThreadAction`) but are
  never used from two at once.
- **A conf can serve sessions on several threads at once:** `-model`
  sharing and listening sockets share confs, and a channel moved to another
  thread keeps its conf. Make the conf immutable after `tlsb_conf_new`, or
  lock its mutable parts (a lazily loaded system store, the client session
  cache). Harness TestThreads runs 6 threads × 8 sessions over one pair of
  confs with a lazily loaded system store.
- **Everything else** (`tlsb_global_init`, `tlsb_conf_new`/`free`,
  `tlsb_ciphers`, the crypto helpers) can come from any thread.

| Backend  | How it copes                                                                             |
|----------|------------------------------------------------------------------------------------------|
| OpenSSL  | system store loaded once; a per-conf lock on the session cache                           |
| wolfSSL  | a per-conf mutex on the lazy system store and session cache; a fixed ticket key per conf |
| Mbed TLS | `MBEDTLS_THREADING_C` when bundled, else one global lock released around callbacks       |
| rustls   | `Arc`s and `OnceLock`s; its ticketer and session store are thread-safe                   |

## 9. Adding a backend to the build

Follow `openssl/`. The directory is named after the backend, a lowercase
bare token:

```
<backend>/backend.c        implements every function in tlsb.h
<backend>/CMakeLists.txt
<backend>/test_backend.c   C harness (picked up automatically)
<backend>/config.h ...     library configuration for a bundled build, if any
```

`<backend>/CMakeLists.txt` for a backend `foo`:

```cmake
set(TLS_FOO AUTO CACHE STRING "Foo: AUTO, BUNDLED or SYSTEM")
set_property(CACHE TLS_FOO PROPERTY STRINGS AUTO BUNDLED SYSTEM)

add_library(foo_backend OBJECT backend.c)
target_include_directories(foo_backend PUBLIC ${PROJECT_SOURCE_DIR}/generic)
tls_warnings(foo_backend)

if(TLS_FOO STREQUAL "SYSTEM" OR (TLS_FOO STREQUAL "AUTO" AND BUILD_SHARED_LIBS))
    find_package(Foo ...)            # REQUIRED for SYSTEM
endif()
if(Foo_FOUND)
    target_link_libraries(foo_backend PUBLIC Foo::foo)
    tls_package(foo OBJECTS foo_backend
        LIBS Foo::foo ${TLS_OS_LIBS} REQUIRES foo)
    return()
endif()

tls_fetch(foo)                       # pinned sources, as ${foo_SOURCE_DIR}
add_library(foo_bundled OBJECT ${sources})
target_link_libraries(foo_backend PUBLIC foo_bundled)
tls_package(foo OBJECTS foo_backend foo_bundled LIBS ${TLS_OS_LIBS})
```

`tls_fetch(foo)` uses the pins `TLS_FOO_VERSION`, `TLS_FOO_URL` and
`TLS_FOO_SHA256` in `cmake/Sources.cmake`, and honours `TLS_SOURCES`.
`tls_package` (`cmake/TlsPackage.cmake`) derives every name from the
backend's:

| Name                         | Value                                                                                                                      |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| Package, Tcl namespace       | `tlschan::<backend>`; `pkgconfig get backend` gives `<backend>`                                                            |
| Target, file stem            | `tlschan_<backend>`                                                                                                        |
| Init function, `load` prefix | `Tlschan_<backend>_Init`, `Tlschan_<backend>`                                                                              |
| Shared module                | `lib/tlschan_<backend>0.1.0/libtcl9tlschan_<backend>0.1.0.so` (Windows `tcl9tlschan_<backend>010.dll`) plus `pkgIndex.tcl` |
| Static archive, pkg-config   | `lib/libtcl9tlschan_<backend>0.1.0.a`, `lib/pkgconfig/tcl9tlschan_<backend>.pc`                                            |
| C harness target             | `tlschan_<backend>_harness`                                                                                                |
| ctest names                  | `<backend>` (Tcl suite), `<backend>-harness` (C harness)                                                                   |

| Argument   | Meaning                                                                                                            |
|------------|--------------------------------------------------------------------------------------------------------------------|
| `OBJECTS`  | Object libraries: your backend plus a bundled library's objects                                                    |
| `ARCHIVES` | Prebuilt static archives (rustls's cargo output `libtlschan_rustls.a`, bundled OpenSSL's `libssl.a`/`libcrypto.a`) |
| `DEPENDS`  | Targets that produce those archives (`rustls_cargo`, `openssl_bundled`)                                            |
| `LIBS`     | External libraries to link: imported targets, `-framework ...`, plain names                                        |
| `REQUIRES` | pkg-config module names of a `SYSTEM` library, for the static `.pc`                                                |

A package defines only `::tlschan::<backend>::*`; the aliases in
`::tlschan` and `::tls` are the umbrella's business (basic-1.2 checks).

Build rules:

- **AUTO, BUNDLED, SYSTEM:** AUTO uses the system library for shared builds
  and bundles it for static ones (OpenSSL, Mbed TLS). wolfSSL's AUTO always
  bundles, and its SYSTEM warns about missing features. rustls has no such
  option; its crates are pinned by `rustls/Cargo.lock`.
- **Public API only:** never reach into the library's private state
  (`MBEDTLS_PRIVATE` and the like). Where the API falls short, accept and
  document the library's behaviour.
- **OS libraries:** `TLS_OS_LIBS` is set by the top-level `CMakeLists.txt`.
  Add anything else your library needs to `LIBS`; rustls lists its own.

  | Platform | Libraries                                          |
  |----------|----------------------------------------------------|
  | Windows  | `ws2_32 crypt32 bcrypt advapi32 user32`            |
  | macOS    | `-framework Security`, `-framework CoreFoundation` |
  | Haiku    | `network`                                          |
  | Others   | `Threads::Threads ${CMAKE_DL_LIBS}`                |

- **Exports:** a module or static archive has one global symbol,
  `Tlschan_<backend>_Init` (static archives are prelinked with `ld -r` by
  `cmake/Prelink.cmake`). So every symbol must resolve through `LIBS`, your
  objects must survive `ld -r`, and nothing may rely on exported or
  interposed symbols. A `SYSTEM` library is not folded in; the `.pc` file
  names it.

To register the backend:

1. Top-level `CMakeLists.txt`: add it to the `all` list, the
   `^(wolfssl|rustls|mbedtls|openssl)$` check, the comment at the top and
   the `TLS_BACKENDS` help string. The loop then runs
   `add_subdirectory(<backend>)`.
2. A bundled library: its pins in `cmake/Sources.cmake` and its name in the
   `foreach` of `cmake/Fetch.cmake`.
3. `tests/basic.test`: the backend name in basic-1.1's
   `{wolfssl rustls mbedtls openssl}`, the library name in basic-2.4's
   version regexp.
4. `tests/interop.test`: the package in
   `foreach other {tlschan::wolfssl tlschan::rustls tlschan::mbedtls tlschan::openssl}`.
5. `generic/tlschan.tcl`: the backend in `Choose`'s default order
   `{openssl rustls mbedtls wolfssl}`.
6. `README.md` tables, if you keep them in step.

`tests/CMakeLists.txt` finds every package by itself.

### The C harness

`<backend>/test_backend.c`, if present, is built without Tcl (not on
Windows) and run by ctest as `<backend>-harness`. All harnesses take:

```
tlschan_<backend>_harness certdir [pkidir] [-nonet] [-host name]...   # cwd tests/certs
```

- `pkidir` enables the expired-chain tests; without `-nonet` it also
  connects to `www.google.com:443` (or each `-host`). It exits nonzero on
  any failure.
- Start from `openssl/test_backend.c`: client and server talk through
  memory pipes, and only `TestLibrary`'s version check is
  library-specific.

## 10. Testing checklist

- [ ] `cmake -B build -DTLS_BACKENDS=foo && cmake --build build && ctest --test-dir build`
  runs `foo-harness` and `foo` (`tests/all.tcl`: basic, conf, io, interop,
  tlschan and www).
- [ ] The harness runs clean, including TestThreads, TestExpired, the
  IP-literal and no-SNI checks, "connection closed during handshake",
  pending after a partial read, TestWantRead, TestResume and TestRefused.
- [ ] conf.test: the exact configuration messages, `-servername` and ALPN
  checks, cipher names in either option and `-` for `_`, `-model` sides and
  anchors, empty callbacks.
- [ ] io-6.1 to io-6.3 (no busy loop), which catch `tlsb_pending` and
  `WANT_READ` mistakes.
- [ ] io-7.*: per-depth verdicts (io-7.2, io-7.3), verification messages,
  no protocol or cipher in common, no ALPN in common (io-7.7), `-password`
  with `return`, a refused `-async` connect, EOF without close_notify.
- [ ] io-8.*: resumption in TLS 1.3 and TLS 1.2 through a conf anchored on
  a plain channel (io-8.1, io-8.2), none with a callback on either side
  (io-8.3, io-8.4).
- [ ] Interop: `-DTLS_BACKENDS=all`; interop.test pairs every client with
  every server.
- [ ] Static: `-DBUILD_SHARED_LIBS=OFF`; the suite runs through a tclsh
  with every package linked in.
- [ ] Network: `-DTLS_TEST_NETWORK=ON` (real hosts, badssl.com).
- [ ] Sanitizers: `-DTLS_SANITIZE=address,undefined`; suppress only
  third-party code, in `tests/ubsan.supp`.
- [ ] Windows: `--toolchain cmake/mingw-w64.cmake`; the Tcl suite runs
  under wine. The DLL must depend on system DLLs only, and the system store
  must work for roots Windows fetches on demand (`tlsb_win_chain`).
