//! Certificate verifiers: webpki decides the verdict, the session policy
//! (require flag and the io->verify callback) decides whether it is fatal.

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr::null;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme,
};

use crate::chain::verdicts;
use crate::errors::{cert_reason, reason};

pub type VerifyFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const u8, usize, c_int, *const c_char) -> c_int;

#[derive(Debug, Clone, Copy)]
pub struct Callback {
    pub f: VerifyFn,
    pub ud: *mut c_void,
}

// Sessions are single-threaded; the callback only runs on the session's thread.
unsafe impl Send for Callback {}
unsafe impl Sync for Callback {}

#[derive(Debug)]
pub struct Policy {
    pub require: bool,
    pub cb: Option<Callback>,
    pub algs: WebPkiSupportedAlgorithms,
    /// The trust store webpki uses, to attribute its verdict to a depth.
    pub roots: Arc<RootCertStore>,
    /// roots is the system store (and how to verify again, see retry).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub system: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub provider: Arc<CryptoProvider>,
}

impl Policy {
    fn needed(&self) -> bool {
        self.require || self.cb.is_some()
    }

    /// Reports each certificate, top first; a bad one taints those below it.
    fn decide(
        &self,
        roots: &RootCertStore,
        chain: &[CertificateDer<'_>],
        name: Option<&ServerName<'_>>,
        now: UnixTime,
        overall: Result<(), Error>,
    ) -> Result<(), Error> {
        if overall.is_ok() && self.cb.is_none() {
            return Ok(());
        }
        let v = verdicts(chain, roots, name, now, &overall);
        let Some(cb) = self.cb else {
            // The topmost failure is the reason.
            return match v.into_iter().rev().flatten().next() {
                Some(e) if self.require => Err(e),
                _ => Ok(()),
            };
        };
        let mut above = None;
        for (depth, own) in v.into_iter().enumerate().rev() {
            let err = own.or_else(|| above.clone());
            let msg = err
                .as_ref()
                .map(|e| CString::new(cert_reason(e)).unwrap_or_default());
            if err.is_some() {
                above = Some(reason("issuer certificate not trusted"));
            }
            let der = chain[depth].as_ref();
            // SAFETY: the io->verify callback with its ud, on the session's thread;
            // `der` and `msg` outlive the call.
            let ok = unsafe {
                (cb.f)(
                    cb.ud,
                    depth as c_int,
                    der.as_ptr(),
                    der.len(),
                    err.is_none() as c_int,
                    msg.as_ref().map_or(null(), |m| m.as_ptr()),
                )
            };
            if ok == 0 {
                return Err(Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(())
    }

    fn tls12(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(m, c, d, &self.algs)
    }

    fn tls13(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(m, c, d, &self.algs)
    }
}

#[derive(Debug)]
pub struct ServerVerifier {
    pub inner: Option<Arc<WebPkiServerVerifier>>,
    /// No servername: verify the chain only.
    pub nameless: bool,
    pub policy: Policy,
}

impl ServerVerifier {
    /// Windows fetches most roots only on demand (see generic/winroot.c): on
    /// an unknown issuer, add the root Windows trusts and verify again, with
    /// the intermediates Windows fetched next to those the peer sent.
    #[cfg(windows)]
    fn retry(
        &self,
        verdict: Result<(), Error>,
        leaf: &CertificateDer<'_>,
        rest: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> (Result<(), Error>, Arc<RootCertStore>) {
        let roots = self.policy.roots.clone();
        if !self.policy.system
            || !matches!(
                verdict,
                Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
            )
        {
            return (verdict, roots);
        }
        let chain = [std::slice::from_ref(leaf), rest].concat();
        let Some((roots, fetched)) = crate::conf::win_fetch(&chain, false) else {
            return (verdict, roots);
        };
        let rest = [rest, &fetched].concat();
        match WebPkiServerVerifier::builder_with_provider(
            roots.clone(),
            self.policy.provider.clone(),
        )
        .build()
        {
            Ok(v) => (
                v.verify_server_cert(leaf, &rest, name, ocsp, now).map(drop),
                roots,
            ),
            Err(_) => (verdict, self.policy.roots.clone()),
        }
    }

    #[cfg(not(windows))]
    fn retry(
        &self,
        verdict: Result<(), Error>,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> (Result<(), Error>, Arc<RootCertStore>) {
        (verdict, self.policy.roots.clone())
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        rest: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !self.policy.needed() {
            return Ok(ServerCertVerified::assertion());
        }
        let verdict = match &self.inner {
            Some(v) => v.verify_server_cert(leaf, rest, name, ocsp, now).map(drop),
            None => Err(Error::General("no trust store".into())),
        };
        let (verdict, roots) = self.retry(verdict, leaf, rest, name, ocsp, now);
        let verdict = match verdict {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) if self.nameless => Ok(()),
            v => v,
        };
        let chain = [std::slice::from_ref(leaf), rest].concat();
        let name = (!self.nameless).then_some(name);
        self.policy
            .decide(&roots, &chain, name, now, verdict)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.policy.tls12(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.policy.tls13(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.algs.supported_schemes()
    }
}

#[derive(Debug)]
pub struct ClientVerifier {
    /// webpki verifier built with allow_unauthenticated; mandatory-ness is ours.
    pub inner: Arc<dyn ClientCertVerifier>,
    pub policy: Policy,
}

impl ClientCertVerifier for ClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.policy.require
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        rest: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !self.policy.needed() {
            return Ok(ClientCertVerified::assertion());
        }
        let verdict = self.inner.verify_client_cert(leaf, rest, now).map(drop);
        let chain = [std::slice::from_ref(leaf), rest].concat();
        self.policy
            .decide(&self.policy.roots, &chain, None, now, verdict)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.policy.tls12(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.policy.tls13(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.algs.supported_schemes()
    }
}
