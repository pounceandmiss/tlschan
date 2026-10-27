//! Per-certificate verdicts. webpki judges a chain as a whole; this
//! attributes a failure to a depth the way the C backends report it.

use rustls::client::verify_server_name;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError as CE, Error, RootCertStore};

use crate::errors::reason;

/// The fields we need, as DER contents.
struct Cert<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    from: i64,
    to: i64,
}

/// One DER TLV: (tag, contents, rest).
fn tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, d) = d.split_first()?;
    let (&b, d) = d.split_first()?;
    let (len, d) = match b {
        0..=0x7f => (b as usize, d),
        0x81..=0x84 => {
            let (l, d) = d.split_at_checked((b & 0x7f) as usize)?;
            (l.iter().fold(0, |a, &x| a << 8 | x as usize), d)
        }
        _ => return None,
    };
    let (v, rest) = d.split_at_checked(len)?;
    Some((tag, v, rest))
}

/// UTCTime or GeneralizedTime (YYYYMMDDHHMMSSZ) as Unix seconds.
fn time(tag: u8, v: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(v).ok().filter(|s| s.is_ascii())?;
    let s = s.strip_suffix('Z')?;
    let (y, s) = match tag {
        0x17 => {
            let y: i64 = s.get(..2)?.parse().ok()?;
            (if y < 50 { 2000 + y } else { 1900 + y }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |i: usize| s.get(i..i + 2)?.parse::<i64>().ok();
    let (mo, d) = (n(0)?, n(2)?);
    if s.len() != 10 || !(1..=12).contains(&mo) {
        return None;
    }
    // Days from the civil date (H. Hinnant).
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + d - 1;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + n(4)? * 3600 + n(6)? * 60 + n(8)?)
}

fn parse(der: &[u8]) -> Option<Cert<'_>> {
    let (_, c, _) = tlv(der)?;
    let (_, mut t, _) = tlv(c)?;
    let mut f = Vec::new();
    while let Some((tag, v, rest)) = tlv(t) {
        f.push((tag, v));
        t = rest;
    }
    // [0] version, serial, signature, issuer, validity, subject, spki
    // Skip the optional [0] version.
    let f = &f[(f.first()?.0 == 0xa0) as usize..];
    let (t1, v1, rest) = tlv(f.get(3)?.1)?;
    let (t2, v2, _) = tlv(rest)?;
    Some(Cert {
        issuer: f.get(2)?.1,
        subject: f.get(4)?.1,
        spki: f.get(5)?.1,
        from: time(t1, v1)?,
        to: time(t2, v2)?,
    })
}

/// Whether c's issuer, or c itself, is in the store.
fn anchored(c: &Cert, roots: &RootCertStore) -> bool {
    roots.roots.iter().any(|a| {
        let s = a.subject.as_ref();
        s == c.issuer || (s == c.subject && a.subject_public_key_info.as_ref() == c.spki)
    })
}

/// Own verdict of each certificate of the sent chain (leaf first), cut where
/// the issuer links break. `overall` is webpki's verdict.
pub fn verdicts(
    chain: &[CertificateDer<'_>],
    roots: &RootCertStore,
    name: Option<&ServerName<'_>>,
    now: UnixTime,
    overall: &Result<(), Error>,
) -> Vec<Option<Error>> {
    let certs: Vec<_> = chain.iter().map(|c| parse(c)).collect();
    // Length of the linked prefix of the chain.
    let mut n = 1;
    while n < certs.len()
        && matches!((&certs[n - 1], &certs[n]), (Some(a), Some(b)) if a.issuer == b.subject)
    {
        n += 1;
    }
    let mut v = vec![None; n.min(chain.len())];
    let Err(e) = overall else { return v };
    if matches!(
        e,
        Error::InvalidCertificate(CE::NotValidForName | CE::NotValidForNameContext { .. })
    ) {
        v[0] = Some(e.clone());
        return v;
    }
    let now = now.as_secs() as i64;
    for (d, c) in certs.iter().take(v.len()).enumerate() {
        v[d] = match c {
            None => Some(Error::InvalidCertificate(CE::BadEncoding)),
            Some(c) if d == v.len() - 1 && !anchored(c, roots) => Some(if c.issuer == c.subject {
                reason("self-signed certificate")
            } else {
                Error::InvalidCertificate(CE::UnknownIssuer)
            }),
            Some(c) if now > c.to => Some(Error::InvalidCertificate(CE::Expired)),
            Some(c) if now < c.from => Some(Error::InvalidCertificate(CE::NotValidYet)),
            _ => None,
        };
    }
    if let (None, Some(name)) = (&v[0], name) {
        v[0] = ParsedCertificate::try_from(&chain[0])
            .and_then(|p| verify_server_name(&p, name))
            .err();
    }
    // Something else (signature, purpose, constraints): blame the leaf.
    if v.iter().all(Option::is_none) {
        v[0] = Some(e.clone());
    }
    v
}

#[cfg(test)]
mod tests {
    #[test]
    fn time() {
        assert_eq!(super::time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(super::time(0x18, b"20210101000000Z"), Some(1609459200));
        assert_eq!(super::time(0x17, b"240229120000Z"), Some(1709208000));
    }
}
