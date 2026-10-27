//! Crypto helpers on top of ring.

use std::num::NonZeroU32;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, pbkdf2};

/// AES-GCM tag length.
pub const TAG: usize = 16;

pub fn random(buf: &mut [u8]) -> bool {
    SystemRandom::new().fill(buf).is_ok()
}

/// TLSB_SHA1, TLSB_SHA256, TLSB_SHA512.
fn digest_alg(alg: i32) -> Option<&'static digest::Algorithm> {
    Some(match alg {
        0 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        1 => &digest::SHA256,
        2 => &digest::SHA512,
        _ => return None,
    })
}

/// Returns the digest length.
pub fn digest(alg: i32, data: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    let d = digest::digest(digest_alg(alg)?, data);
    out[..d.as_ref().len()].copy_from_slice(d.as_ref());
    Some(d.as_ref().len())
}

pub fn pbkdf2(alg: i32, pw: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> bool {
    let alg = match alg {
        0 => pbkdf2::PBKDF2_HMAC_SHA1,
        1 => pbkdf2::PBKDF2_HMAC_SHA256,
        2 => pbkdf2::PBKDF2_HMAC_SHA512,
        _ => return false,
    };
    let Some(n) = NonZeroU32::new(iterations) else {
        return false;
    };
    pbkdf2::derive(alg, n, salt, pw, out);
    true
}

fn key(k: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).expect("32-byte AES key"))
}

/// Encrypts `buf` in place; `out` gets ciphertext || tag.
pub fn seal(k: &[u8; 32], nonce: [u8; 12], mut buf: Vec<u8>, out: &mut [u8]) -> bool {
    match key(k).seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut buf,
    ) {
        Ok(()) => {
            out.copy_from_slice(&buf);
            true
        }
        Err(_) => false,
    }
}

/// Decrypts ciphertext || tag in `buf`; `out` gets the plaintext.
pub fn open(k: &[u8; 32], nonce: [u8; 12], mut buf: Vec<u8>, out: &mut [u8]) -> bool {
    match key(k).open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf) {
        Ok(pt) => {
            out.copy_from_slice(pt);
            true
        }
        Err(_) => false,
    }
}
