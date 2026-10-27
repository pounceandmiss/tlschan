//! rustls backend for the Tcl TLS channel layer: the C ABI of generic/tlsb.h.
//! Built with panic=abort, so no unwinding can cross into C.
//! Safety: every pointer argument follows the tlsb.h contract.
#![allow(clippy::missing_safety_doc, non_camel_case_types)]

mod chain;
mod conf;
mod crypto;
mod errors;
mod sess;
mod verify;

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use conf::{Conf, Opts};
use sess::{Io, Sess, ERROR, OK};

#[repr(C)]
pub struct tlsb_opts {
    server: c_int,
    request: c_int,
    require: c_int,
    protocols: c_uint,
    ca: *const u8,
    ca_len: usize,
    cadir: *const c_char,
    cert: *const u8,
    cert_len: usize,
    key: *const u8,
    key_len: usize,
    password: *const c_char,
    ciphers: *const c_char,
    ciphersuites: *const c_char,
    alpn: *const *const c_char,
    alpn_count: c_int,
}

#[repr(C)]
pub struct tlsb_info {
    protocol: *const c_char,
    cipher: *const c_char,
    cipher_bits: c_int,
    alpn: *const u8,
    alpn_len: usize,
    servername: *const c_char,
    resumed: c_int,
}

/// A C buffer as a slice; NULL or empty gives an empty slice.
unsafe fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, len)
    }
}

/// A C output buffer as a slice; NULL or empty gives an empty slice.
unsafe fn slice_mut<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    if p.is_null() || len == 0 {
        &mut []
    } else {
        std::slice::from_raw_parts_mut(p, len)
    }
}

/// An optional input buffer: None when NULL or empty.
unsafe fn blob<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    Some(slice(p, len)).filter(|s| !s.is_empty())
}

/// An optional C string, which must be UTF-8.
unsafe fn cstr<'a>(p: *const c_char) -> Result<Option<&'a str>, String> {
    if p.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(p)
        .to_str()
        .map(Some)
        .map_err(|_| "string is not valid UTF-8".into())
}

/// Copies `msg` into the caller's error buffer, truncated and NUL-terminated.
unsafe fn put_err(err: *mut c_char, len: usize, msg: &str) {
    if err.is_null() || len == 0 {
        return;
    }
    let n = msg.len().min(len - 1);
    std::ptr::copy_nonoverlapping(msg.as_ptr(), err.cast(), n);
    *err.add(n) = 0;
}

/// TLSB_OK or TLSB_ERROR.
fn rc(ok: bool) -> c_int {
    if ok {
        OK
    } else {
        ERROR
    }
}

#[no_mangle]
pub extern "C" fn tlsb_global_init(_err: *mut c_char, _errlen: usize) -> c_int {
    OK
}

#[no_mangle]
pub extern "C" fn tlsb_version() -> *const c_char {
    concat!("rustls ", env!("RUSTLS_VERSION"), "\0")
        .as_ptr()
        .cast()
}

#[no_mangle]
pub extern "C" fn tlsb_protocols() -> c_uint {
    conf::TLS12 | conf::TLS13
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_ciphers(
    protocols: c_uint,
    cb: Option<unsafe extern "C" fn(*mut c_void, *const c_char)>,
    ud: *mut c_void,
) {
    let (Some(cb), Ok(versions)) = (cb, conf::versions(protocols)) else {
        return;
    };
    for s in rustls::crypto::ring::default_provider().cipher_suites {
        if versions.contains(&s.version()) {
            if let Ok(name) = std::ffi::CString::new(conf::iana(s.suite())) {
                cb(ud, name.as_ptr());
            }
        }
    }
}

/// Borrows the C options as Rust values; the ALPN names are copied.
unsafe fn opts<'a>(o: &'a tlsb_opts) -> Result<Opts<'a>, String> {
    let alpn = match o.alpn_count {
        n if n > 0 && !o.alpn.is_null() => std::slice::from_raw_parts(o.alpn, n as usize)
            .iter()
            .filter(|p| !p.is_null())
            .map(|&p| CStr::from_ptr(p).to_bytes().to_vec())
            .collect(),
        _ => Vec::new(),
    };
    Ok(Opts {
        server: o.server != 0,
        request: o.request != 0,
        require: o.require != 0,
        protocols: o.protocols,
        ca: blob(o.ca, o.ca_len),
        cadir: cstr(o.cadir)?.map(Path::new),
        cert: blob(o.cert, o.cert_len),
        key: blob(o.key, o.key_len),
        password: cstr(o.password)?,
        ciphers: cstr(o.ciphers)?,
        ciphersuites: cstr(o.ciphersuites)?,
        alpn,
    })
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_conf_new(
    o: *const tlsb_opts,
    err: *mut c_char,
    errlen: usize,
) -> *mut Conf {
    let Some(o) = o.as_ref() else {
        return null_mut();
    };
    match opts(o).and_then(|o| Conf::new(&o)) {
        Ok(c) => Arc::into_raw(Arc::new(c)).cast_mut(),
        Err(e) => {
            put_err(err, errlen, &e);
            null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_conf_free(c: *mut Conf) {
    if !c.is_null() {
        drop(Arc::from_raw(c));
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_sess_new(
    c: *mut Conf,
    servername: *const c_char,
    io: *const Io,
    err: *mut c_char,
    errlen: usize,
) -> *mut Sess {
    let (Some(_), Some(io)) = (c.as_ref(), io.as_ref()) else {
        put_err(err, errlen, "missing configuration or io");
        return null_mut();
    };
    // The session holds a reference of its own, so the conf may be freed first.
    Arc::increment_strong_count(c);
    let conf = Arc::from_raw(c);
    match cstr(servername).and_then(|n| Sess::new(conf, n, io)) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(e) => {
            put_err(err, errlen, &e);
            null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_sess_free(s: *mut Sess) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_errmsg(s: *mut Sess) -> *const c_char {
    s.as_ref()
        .and_then(Sess::errmsg)
        .map_or(c"unknown error".as_ptr(), |m| m.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_handshake(s: *mut Sess) -> c_int {
    s.as_mut().map_or(ERROR, Sess::handshake)
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_read(s: *mut Sess, buf: *mut u8, len: usize) -> c_long {
    s.as_mut()
        .map_or(ERROR.into(), |s| s.read(slice_mut(buf, len)))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_write(s: *mut Sess, buf: *const u8, len: usize) -> c_long {
    s.as_mut()
        .map_or(ERROR.into(), |s| s.write(slice(buf, len)))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_pending(s: *mut Sess) -> c_int {
    s.as_mut().is_some_and(Sess::pending).into()
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_close_notify(s: *mut Sess) {
    if let Some(s) = s.as_mut() {
        s.close_notify();
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_info_get(s: *mut Sess, out: *mut tlsb_info) -> c_int {
    let (Some(s), Some(out)) = (s.as_mut(), out.as_mut()) else {
        return ERROR;
    };
    let Some(i) = s.info() else { return ERROR };
    *out = tlsb_info {
        protocol: i.protocol.as_ptr(),
        cipher: i.cipher.as_ptr(),
        cipher_bits: i.bits,
        alpn: i.alpn.map_or(null(), <[u8]>::as_ptr),
        alpn_len: i.alpn.map_or(0, <[u8]>::len),
        servername: i.servername.map_or(null(), |n| n.as_ptr()),
        resumed: i.resumed.into(),
    };
    OK
}

/// Hands out a DER certificate borrowed from the session.
unsafe fn put_der(d: Option<&[u8]>, der: *mut *const u8, len: *mut usize) -> c_int {
    match (d, der.as_mut(), len.as_mut()) {
        (Some(d), Some(p), Some(l)) => {
            (*p, *l) = (d.as_ptr(), d.len());
            OK
        }
        _ => ERROR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_peer_cert(
    s: *mut Sess,
    depth: c_int,
    der: *mut *const u8,
    len: *mut usize,
) -> c_int {
    let d = s
        .as_ref()
        .zip(usize::try_from(depth).ok())
        .and_then(|(s, d)| s.peer_cert(d));
    put_der(d, der, len)
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_local_cert(
    s: *mut Sess,
    der: *mut *const u8,
    len: *mut usize,
) -> c_int {
    put_der(s.as_ref().and_then(Sess::local_cert), der, len)
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_export(
    s: *mut Sess,
    label: *const c_char,
    label_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    use_ctx: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let Some(s) = s.as_ref() else { return ERROR };
    let ctx = (use_ctx != 0).then(|| slice(ctx, ctx_len));
    rc(!out.is_null() && s.export(slice(label.cast(), label_len), ctx, slice_mut(out, out_len)))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_random(buf: *mut u8, len: usize) -> c_int {
    rc(len == 0 || (!buf.is_null() && crypto::random(slice_mut(buf, len))))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_digest(
    alg: c_int,
    data: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    // tlsb.h: `out` holds 64 bytes, enough for any supported digest.
    let Some(out) = out.cast::<[u8; 64]>().as_mut() else {
        return ERROR;
    };
    rc(crypto::digest(alg, slice(data, len), out).is_some())
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_pbkdf2(
    alg: c_int,
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    rc(!out.is_null()
        && crypto::pbkdf2(
            alg,
            slice(pw, pw_len),
            slice(salt, salt_len),
            iterations,
            slice_mut(out, out_len),
        ))
}

/// The fixed-size AES-256-GCM key and nonce, or None if either is NULL.
unsafe fn key_nonce(key: *const u8, nonce: *const u8) -> Option<(&'static [u8; 32], [u8; 12])> {
    Some((
        key.cast::<[u8; 32]>().as_ref()?,
        *nonce.cast::<[u8; 12]>().as_ref()?,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_aes256gcm_seal(
    key: *const u8,
    nonce: *const u8,
    inp: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    let Some((k, n)) = key_nonce(key, nonce).filter(|_| !out.is_null()) else {
        return ERROR;
    };
    // Copy the input first: `inp` and `out` may be the same buffer.
    let pt = slice(inp, len).to_vec();
    rc(crypto::seal(k, n, pt, slice_mut(out, len + crypto::TAG)))
}

#[no_mangle]
pub unsafe extern "C" fn tlsb_aes256gcm_open(
    key: *const u8,
    nonce: *const u8,
    inp: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    let Some((k, n)) = key_nonce(key, nonce)
        .filter(|_| len >= crypto::TAG && (len == crypto::TAG || !out.is_null()))
    else {
        return ERROR;
    };
    // Copy the input first: `inp` and `out` may be the same buffer.
    let ct = slice(inp, len).to_vec();
    rc(crypto::open(k, n, ct, slice_mut(out, len - crypto::TAG)))
}
