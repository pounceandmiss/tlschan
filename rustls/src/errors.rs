//! Human readable messages for rustls errors.

use std::fmt;
use std::sync::Arc;

use rustls::{CertificateError as CE, Error, OtherError};

/// A verification reason of our own, carried in CertificateError::Other.
#[derive(Debug)]
struct Reason(&'static str);

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Reason {}

pub fn reason(r: &'static str) -> Error {
    Error::InvalidCertificate(CE::Other(OtherError(Arc::new(Reason(r)))))
}

/// "UnknownCA" -> "unknown CA"; drops any `{ .. }`/`( .. )` payload.
fn words(debug: &str) -> String {
    let name: Vec<char> = debug
        .split(['{', '(', ' '])
        .next()
        .unwrap_or(debug)
        .chars()
        .collect();
    let lower = |j: usize| name.get(j).is_some_and(char::is_ascii_lowercase);
    // A new word starts at a capital next to a lowercase letter, so that
    // "UnknownCA" splits as "Unknown" "CA" and "CAUsed" as "CA" "Used".
    let mut words: Vec<String> = Vec::new();
    for (i, &c) in name.iter().enumerate() {
        let starts =
            c.is_ascii_uppercase() && (i.checked_sub(1).is_some_and(lower) || lower(i + 1));
        match words.last_mut() {
            Some(w) if !starts => w.push(c),
            _ => words.push(c.into()),
        }
    }
    words
        .iter()
        .map(|w| {
            let acronym = w.len() > 1 && !w.chars().any(|c| c.is_ascii_lowercase());
            if acronym {
                w.clone()
            } else {
                w.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The reason for one certificate, as given to the verify callback.
pub fn cert_reason(e: &Error) -> String {
    let Error::InvalidCertificate(e) = e else {
        return describe(e);
    };
    match e {
        CE::NotValidForName | CE::NotValidForNameContext { .. } => "hostname mismatch".into(),
        CE::UnknownIssuer => "unable to get local issuer certificate".into(),
        CE::Expired | CE::ExpiredContext { .. } => "certificate has expired".into(),
        CE::NotValidYet | CE::NotValidYetContext { .. } => "certificate is not yet valid".into(),
        CE::BadEncoding => "cannot parse certificate".into(),
        CE::InvalidPurpose | CE::InvalidPurposeContext { .. } => {
            "unsupported certificate purpose".into()
        }
        CE::Other(o) => match o.0.downcast_ref::<Reason>() {
            Some(r) => r.0.into(),
            None => match o.to_string().as_str() {
                "CaUsedAsEndEntity" => "CA certificate used as end entity".into(),
                s => words(s),
            },
        },
        e => words(&format!("{e:?}")),
    }
}

pub fn describe(e: &Error) -> String {
    match e {
        Error::InvalidCertificate(CE::ApplicationVerificationFailure) => {
            "certificate rejected by validation callback".into()
        }
        Error::InvalidCertificate(_) => format!("certificate verify failed: {}", cert_reason(e)),
        Error::NoCertificatesPresented => "peer did not return a certificate".into(),
        Error::AlertReceived(a) => format!("peer sent alert: {}", words(&format!("{a:?}"))),
        Error::PeerIncompatible(p) => format!("peer incompatible: {}", words(&format!("{p:?}"))),
        Error::PeerMisbehaved(p) => format!("peer misbehaved: {}", words(&format!("{p:?}"))),
        Error::NoApplicationProtocol => "no common application protocol (ALPN)".into(),
        Error::InconsistentKeys(_) => "private key does not match certificate".into(),
        e => e.to_string(),
    }
}
