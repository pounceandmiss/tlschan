//! Configuration: credential and trust loading, cipher selection, and
//! per-session rustls configs.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{NoServerSessionStorage, VerifierBuilderError, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, Error, InconsistentKeys, ProtocolVersion,
    RootCertStore, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
};

use crate::verify::{Callback, ClientVerifier, Policy, ServerVerifier};

pub const TLS12: u32 = 1;
pub const TLS13: u32 = 2;

pub struct Opts<'a> {
    pub server: bool,
    pub request: bool,
    pub require: bool,
    pub protocols: u32,
    pub ca: Option<&'a [u8]>,
    pub cadir: Option<&'a Path>,
    pub cert: Option<&'a [u8]>,
    pub key: Option<&'a [u8]>,
    pub password: Option<&'a str>,
    pub ciphers: Option<&'a str>,
    pub ciphersuites: Option<&'a str>,
    pub alpn: Vec<Vec<u8>>,
}

pub struct Conf {
    core: Core,
    /// Our own certificate, for tlsb_local_cert.
    pub local: Option<CertificateDer<'static>>,
    side: Side,
}

/// What session configs are derived from.
struct Core {
    provider: Arc<CryptoProvider>,
    require: bool,
    /// The ca/cadir options; None means the system store.
    roots: Option<Arc<RootCertStore>>,
    /// Built on first use, so a client that never verifies loads no roots.
    webpki: OnceLock<Result<Arc<WebPkiServerVerifier>, String>>,
}

enum Side {
    Client {
        /// Template for sessions with a verify callback.
        base: Box<ClientConfig>,
        /// Shared by sessions without a callback, with and without servername.
        named: Arc<ClientConfig>,
        nameless: Arc<ClientConfig>,
    },
    Server {
        /// With and without ALPN: no overlap means no ALPN, not a failure.
        base: Arc<ServerConfig>,
        bare: Arc<ServerConfig>,
        /// The webpki client verifier, when client certificates are requested.
        auth: Option<Arc<dyn ClientCertVerifier>>,
        versions: Vec<&'static SupportedProtocolVersion>,
        key: Arc<CertifiedKey>,
        alpn: Vec<Vec<u8>>,
    },
}

type R<T> = Result<T, String>;

impl Conf {
    pub fn new(o: &Opts) -> R<Conf> {
        if o.alpn.iter().any(|p| p.is_empty() || p.len() > 255) {
            return Err("invalid ALPN protocol name".into());
        }
        // An empty protocol set is reported as such, not as missing ciphers.
        versions(o.protocols)?;
        let mut provider = ring::default_provider();
        let protocols;
        (provider.cipher_suites, protocols) = suites(
            &provider.cipher_suites,
            o.ciphers,
            o.ciphersuites,
            o.protocols,
        )?;
        let versions = versions(protocols)?;
        let roots = explicit_roots(o.ca, o.cadir)?;
        if o.cert.is_some() != o.key.is_some() {
            return Err("certificate and private key go together".into());
        }
        let key = o
            .cert
            .zip(o.key)
            .map(|(c, k)| certified_key(&provider, c, k, o.password))
            .transpose()?;
        let core = Core {
            provider: Arc::new(provider),
            require: o.require,
            roots,
            webpki: OnceLock::new(),
        };
        let local = key.as_ref().map(|k| k.cert[0].clone());
        let side = if o.server {
            let key = key.ok_or("server requires a certificate and key")?;
            core.server_side(o, versions, key)?
        } else {
            core.client_side(o, &versions, key)?
        };
        Ok(Conf { core, local, side })
    }

    pub fn is_server(&self) -> bool {
        matches!(self.side, Side::Server { .. })
    }

    pub fn client(&self, servername: Option<&str>, cb: Option<Callback>) -> R<ClientConnection> {
        let Side::Client {
            base,
            named,
            nameless,
        } = &self.side
        else {
            return Err("not a client configuration".into());
        };
        let name = match servername {
            Some(n) => ServerName::try_from(n.to_owned())
                .map_err(|_| format!("invalid server name: {n}"))?,
            // An IP placeholder makes rustls send no SNI.
            None => ServerName::IpAddress(Ipv4Addr::UNSPECIFIED.into()),
        };
        let cfg = match (cb, servername) {
            (Some(_), _) => Arc::new(self.core.client_variant(base, servername.is_none(), cb)?),
            (None, Some(_)) => named.clone(),
            (None, None) => nameless.clone(),
        };
        ClientConnection::new(cfg, name).map_err(|e| e.to_string())
    }

    /// The config for a server session, given the ALPN list the client offered.
    pub fn server(
        &self,
        offered: Option<Vec<&[u8]>>,
        cb: Option<Callback>,
    ) -> R<Arc<ServerConfig>> {
        let Side::Server {
            base,
            bare,
            auth,
            versions,
            key,
            alpn,
        } = &self.side
        else {
            return Err("not a server configuration".into());
        };
        let overlap = offered.is_none_or(|o| o.iter().any(|p| alpn.iter().any(|a| a == p)));
        let (base, bare) = match (cb, auth) {
            (Some(cb), Some(inner)) => {
                let v = Arc::new(ClientVerifier {
                    inner: inner.clone(),
                    policy: self.core.policy(Some(cb), self.core.trust()),
                });
                let mut c = self.core.server_config(versions, key, alpn, v)?;
                // Resumption would skip the callback.
                c.session_storage = Arc::new(NoServerSessionStorage {});
                c.send_tls13_tickets = 0;
                with_and_without_alpn(c)
            }
            _ => (base.clone(), bare.clone()),
        };
        Ok(if overlap { base } else { bare })
    }
}

fn with_and_without_alpn(c: ServerConfig) -> (Arc<ServerConfig>, Arc<ServerConfig>) {
    let mut bare = c.clone();
    bare.alpn_protocols.clear();
    (Arc::new(c), Arc::new(bare))
}

impl Core {
    fn server_side(
        &self,
        o: &Opts,
        versions: Vec<&'static SupportedProtocolVersion>,
        key: Arc<CertifiedKey>,
    ) -> R<Side> {
        let auth = (o.request || o.require)
            .then(|| self.client_auth())
            .transpose()?;
        let verifier: Arc<dyn ClientCertVerifier> = match &auth {
            Some(inner) => Arc::new(ClientVerifier {
                inner: inner.clone(),
                policy: self.policy(None, self.trust()),
            }),
            None => WebPkiClientVerifier::no_client_auth(),
        };
        let mut base = self.server_config(&versions, &key, &o.alpn, verifier)?;
        // Tickets with a key of this conf, TLS 1.2 and 1.3.
        base.ticketer = ring::Ticketer::new().map_err(|e| e.to_string())?;
        let (base, bare) = with_and_without_alpn(base);
        Ok(Side::Server {
            base,
            bare,
            auth,
            versions,
            key,
            alpn: o.alpn.clone(),
        })
    }

    fn client_side(
        &self,
        o: &Opts,
        versions: &[&'static SupportedProtocolVersion],
        key: Option<Arc<CertifiedKey>>,
    ) -> R<Side> {
        let b = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(self.server_verifier(false, None)?);
        let mut base = match key {
            Some(k) => b.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(k))),
            None => b.with_no_client_auth(),
        };
        base.alpn_protocols = o.alpn.clone();
        // Latest sessions of the last 32 servernames.
        base.resumption = Resumption::in_memory_sessions(32);
        let named = Arc::new(base.clone());
        let nameless = Arc::new(self.client_variant(&base, true, None)?);
        Ok(Side::Client {
            base: Box::new(base),
            named,
            nameless,
        })
    }

    fn policy(&self, cb: Option<Callback>, roots: Arc<RootCertStore>) -> Policy {
        Policy {
            require: self.require,
            cb,
            algs: self.provider.signature_verification_algorithms,
            roots,
            system: self.roots.is_none(),
            provider: self.provider.clone(),
        }
    }

    fn trust(&self) -> Arc<RootCertStore> {
        self.roots.clone().unwrap_or_else(system_roots)
    }

    fn server_verifier(&self, nameless: bool, cb: Option<Callback>) -> R<Arc<ServerVerifier>> {
        let needed = self.require || cb.is_some();
        let (inner, roots) = if needed {
            let webpki = self.webpki.get_or_init(|| {
                WebPkiServerVerifier::builder_with_provider(self.trust(), self.provider.clone())
                    .build()
                    .map_err(builder_err)
            });
            (Some(webpki.clone()?), self.trust())
        } else {
            (None, Arc::new(RootCertStore::empty()))
        };
        Ok(Arc::new(ServerVerifier {
            inner,
            nameless,
            policy: self.policy(cb, roots),
        }))
    }

    fn client_variant(
        &self,
        base: &ClientConfig,
        nameless: bool,
        cb: Option<Callback>,
    ) -> R<ClientConfig> {
        let mut c = base.clone();
        c.dangerous()
            .set_certificate_verifier(self.server_verifier(nameless, cb)?);
        // Nameless sessions have no cache key; callback sessions must see the chain.
        c.resumption = Resumption::disabled();
        Ok(c)
    }

    fn client_auth(&self) -> R<Arc<dyn ClientCertVerifier>> {
        let b = WebPkiClientVerifier::builder_with_provider(self.trust(), self.provider.clone())
            .allow_unauthenticated();
        // Don't advertise the whole system store as acceptable issuers.
        let b = if self.roots.is_some() {
            b
        } else {
            b.clear_root_hint_subjects()
        };
        b.build().map_err(builder_err)
    }

    fn server_config(
        &self,
        versions: &[&'static SupportedProtocolVersion],
        key: &Arc<CertifiedKey>,
        alpn: &[Vec<u8>],
        verifier: Arc<dyn ClientCertVerifier>,
    ) -> R<ServerConfig> {
        let mut c = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key.clone())));
        c.alpn_protocols = alpn.to_vec();
        Ok(c)
    }
}

fn builder_err(e: VerifierBuilderError) -> String {
    match e {
        VerifierBuilderError::NoRootAnchors => "no trusted CA certificates".into(),
        e => e.to_string(),
    }
}

static SYSTEM: Mutex<Option<Arc<RootCertStore>>> = Mutex::new(None);

fn system_roots() -> Arc<RootCertStore> {
    SYSTEM
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(|| {
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            #[cfg(feature = "webpki-roots-fallback")]
            if store.is_empty() {
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            Arc::new(store)
        })
        .clone()
}

/// Windows fetches most roots only on demand (see generic/winroot.c): adds
/// the root Windows trusts the chain (leaf first) through to the system
/// store, and returns the store with the intermediates Windows fetched,
/// which only help verify this chain; None if Windows found nothing.
#[cfg(windows)]
pub fn win_fetch(
    chain: &[CertificateDer<'_>],
    server: bool,
) -> Option<(Arc<RootCertStore>, Vec<CertificateDer<'static>>)> {
    use std::ffi::{c_int, c_void};
    type AddFn = unsafe extern "C" fn(*mut c_void, *const u8, usize, c_int);
    extern "C" {
        fn tlsb_win_chain(
            der: *const *const u8,
            len: *const usize,
            n: c_int,
            server: c_int,
            add: AddFn,
            ud: *mut c_void,
        ) -> c_int;
    }
    #[derive(Default)]
    struct Found {
        roots: Vec<Vec<u8>>,
        intermediates: Vec<CertificateDer<'static>>,
    }
    unsafe extern "C" fn add(ud: *mut c_void, der: *const u8, len: usize, root: c_int) {
        // SAFETY: ud is the Found below; der/len a certificate CryptoAPI owns.
        let found = unsafe { &mut *(ud as *mut Found) };
        let der = unsafe { std::slice::from_raw_parts(der, len) }.to_vec();
        if root != 0 {
            found.roots.push(der);
        } else {
            found.intermediates.push(CertificateDer::from(der));
        }
    }
    let der: Vec<*const u8> = chain.iter().map(|c| c.as_ptr()).collect();
    let len: Vec<usize> = chain.iter().map(|c| c.len()).collect();
    let mut found = Found::default();
    // SAFETY: der/len describe chain.len() live buffers; add only runs
    // during the call.
    let n = unsafe {
        tlsb_win_chain(
            der.as_ptr(),
            len.as_ptr(),
            chain.len() as c_int,
            server as c_int,
            add,
            &mut found as *mut Found as *mut c_void,
        )
    };
    if n == 0 {
        return None;
    }
    let mut guard = SYSTEM.lock().unwrap_or_else(PoisonError::into_inner);
    let current = guard.clone()?;
    let mut store = (*current).clone();
    for c in found.roots {
        let c = CertificateDer::from(c);
        let before = store.roots.len();
        if store.add(c).is_ok() && store.roots.len() > before {
            let (new, old) = store.roots.split_last()?;
            if old.contains(new) {
                store.roots.pop();
            }
        }
    }
    if store.roots.len() == current.roots.len() {
        return Some((current, found.intermediates));
    }
    let store = Arc::new(store);
    *guard = Some(store.clone());
    Some((store, found.intermediates))
}

fn explicit_roots(ca: Option<&[u8]>, cadir: Option<&Path>) -> R<Option<Arc<RootCertStore>>> {
    if ca.is_none() && cadir.is_none() {
        return Ok(None);
    }
    let mut store = RootCertStore::empty();
    let bad = || String::from("cannot parse CA certificates");
    let ca = ca.map(certs).transpose().map_err(|_| bad())?;
    for c in ca.unwrap_or_default() {
        store.add(c).map_err(|_| bad())?;
    }
    if let Some(dir) = cadir {
        let entries =
            fs::read_dir(dir).map_err(|_| format!("cannot read cadir: {}", dir.display()))?;
        for path in entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| is_ca_file(p))
        {
            if let Ok(data) = fs::read(&path) {
                store.add_parsable_certificates(CertificateDer::pem_slice_iter(&data).flatten());
            }
        }
    }
    Ok(Some(Arc::new(store)))
}

/// *.pem, *.crt or an OpenSSL hash link like 1a2b3c4d.0
fn is_ca_file(p: &Path) -> bool {
    let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let hashed = n.split_once('.').is_some_and(|(h, i)| {
        h.len() == 8
            && h.bytes().all(|b| b.is_ascii_hexdigit())
            && !i.is_empty()
            && i.bytes().all(|b| b.is_ascii_digit())
    });
    hashed || n.ends_with(".pem") || n.ends_with(".crt")
}

fn is_pem(d: &[u8]) -> bool {
    d.windows(11).any(|w| w == b"-----BEGIN ")
}

pub fn certs(d: &[u8]) -> R<Vec<CertificateDer<'static>>> {
    if !is_pem(d) {
        return Ok(vec![CertificateDer::from(d.to_vec())]);
    }
    match CertificateDer::pem_slice_iter(d).collect::<Result<Vec<_>, _>>() {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err("cannot parse certificate".into()),
    }
}

fn private_key(d: &[u8], password: Option<&str>) -> R<PrivateKeyDer<'static>> {
    let bad = || String::from("cannot parse private key");
    if is_pem(d) {
        match pem_section(d, "ENCRYPTED PRIVATE KEY") {
            Some(der) => decrypt(&der, password),
            None => PrivateKeyDer::from_pem_slice(d).map_err(|_| bad()),
        }
    } else if pkcs8::EncryptedPrivateKeyInfo::try_from(d).is_ok() {
        decrypt(d, password)
    } else {
        PrivateKeyDer::try_from(d)
            .map(|k| k.clone_key())
            .map_err(|_| bad())
    }
}

fn pem_section(d: &[u8], label: &str) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(d).ok()?;
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let a = s.find(&begin)?;
    let b = a + s[a..].find(&end)? + end.len();
    pkcs8::der::pem::decode_vec(&s.as_bytes()[a..b])
        .ok()
        .map(|(_, der)| der)
}

fn decrypt(der: &[u8], password: Option<&str>) -> R<PrivateKeyDer<'static>> {
    let pw = password.ok_or("password required")?;
    let info = pkcs8::EncryptedPrivateKeyInfo::try_from(der)
        .map_err(|_| "cannot parse encrypted private key")?;
    let doc = info.decrypt(pw).map_err(|_| "wrong password")?;
    Ok(PrivateKeyDer::Pkcs8(doc.as_bytes().to_vec().into()))
}

fn certified_key(
    p: &CryptoProvider,
    cert: &[u8],
    key: &[u8],
    pw: Option<&str>,
) -> R<Arc<CertifiedKey>> {
    let chain = certs(cert)?;
    let der = private_key(key, pw)?;
    let sk = p
        .key_provider
        .load_private_key(der)
        .map_err(|e| format!("unsupported private key: {e}"))?;
    let ck = CertifiedKey::new(chain, sk);
    match ck.keys_match() {
        Ok(()) | Err(Error::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(Arc::new(ck)),
        Err(Error::InconsistentKeys(_)) => Err("private key does not match certificate".into()),
        Err(_) => Err("cannot parse certificate".into()),
    }
}

pub fn versions(bits: u32) -> R<Vec<&'static SupportedProtocolVersion>> {
    let bits = if bits == 0 { TLS12 | TLS13 } else { bits };
    let v: Vec<_> = [
        (TLS13, &rustls::version::TLS13),
        (TLS12, &rustls::version::TLS12),
    ]
    .into_iter()
    .filter(|(b, _)| bits & b != 0)
    .map(|(_, v)| v)
    .collect();
    if v.is_empty() {
        Err("no supported protocol version enabled".into())
    } else {
        Ok(v)
    }
}

/// IANA name; rustls spells the TLS 1.3 ones "TLS13_*".
pub fn iana(cs: CipherSuite) -> String {
    match cs.as_str() {
        Some(s) => s.replacen("TLS13_", "TLS_", 1),
        None => format!("0x{:04X}", u16::from(cs)),
    }
}

const OPENSSL_NAMES: [(&str, &str); 6] = [
    (
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ),
    (
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ),
    (
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    (
        "ECDHE-RSA-AES128-GCM-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ),
    (
        "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ),
    (
        "ECDHE-RSA-CHACHA20-POLY1305",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
];

fn norm(s: &str) -> String {
    s.to_ascii_uppercase().replace('-', "_")
}

fn parse_suites(list: &str, all: &[SupportedCipherSuite]) -> R<Vec<SupportedCipherSuite>> {
    list.split(|c: char| c == ':' || c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(|tok| {
            let t = norm(tok);
            let t = OPENSSL_NAMES
                .iter()
                .find(|(o, _)| norm(o) == t)
                .map_or(t, |(_, i)| i.to_string());
            all.iter()
                .copied()
                .find(|s| iana(s.suite()) == t || s.suite().as_str() == Some(&t))
                .ok_or_else(|| format!("unknown cipher: {tok}"))
        })
        .collect()
}

/// Names of either protocol may appear in either option. A given option
/// replaces its protocol's defaults and disables it when it names none.
fn suites(
    all: &[SupportedCipherSuite],
    ciphers: Option<&str>,
    ciphersuites: Option<&str>,
    protocols: u32,
) -> R<(Vec<SupportedCipherSuite>, u32)> {
    let mut named = Vec::new();
    for l in [ciphersuites, ciphers].into_iter().flatten() {
        named.extend(parse_suites(l, all)?);
    }
    let mut bits = if protocols == 0 {
        TLS12 | TLS13
    } else {
        protocols
    };
    let mut out: Vec<SupportedCipherSuite> = Vec::new();
    for (b, v, opt) in [
        (TLS13, ProtocolVersion::TLSv1_3, ciphersuites),
        (TLS12, ProtocolVersion::TLSv1_2, ciphers),
    ] {
        let from = if opt.is_some() { &named[..] } else { all };
        let n = out.len();
        for s in from.iter().filter(|s| s.version().version == v) {
            if !out.iter().any(|o| o.suite() == s.suite()) {
                out.push(*s);
            }
        }
        if out.len() == n {
            bits &= !b;
        }
    }
    if bits & (TLS12 | TLS13) == 0 {
        return Err("no usable cipher suites".into());
    }
    Ok((out, bits))
}
