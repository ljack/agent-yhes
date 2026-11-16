//! Public data only. No key generation, signing, enrollment, I/O or environment.
//! The native signer statically links this bridge to the same cryptographic primitive
//! implementations used by yhes-wire, rather than reimplementing curve checks.

use std::{panic::catch_unwind, slice};
use yhes_wire::{Algorithm, PublicKey};

/// Return 1 for a valid key, 0 for malformed/unsupported input or a panic.
/// Algorithm 1 is Ed25519 (32 raw bytes); 2 is P-256 (65 uncompressed SEC1 bytes).
///
/// Null pointers, unsupported algorithms and wrong lengths fail before reads.
///
/// # Safety
/// For a supported algorithm and exact length, a nonnull `bytes` must point to
/// that many readable bytes for the duration of the call. No C ABI can establish
/// arbitrary pointer validity. The Swift shim supplies a scoped Data buffer.
#[no_mangle]
pub unsafe extern "C" fn yhes_wire_public_key_is_valid(
    algorithm: u32,
    bytes: *const u8,
    length: usize,
) -> u8 {
    let algorithm = match (algorithm, length) {
        (1, 32) => Algorithm::Ed25519,
        (2, 65) => Algorithm::P256Sha256,
        _ => return 0,
    };
    if bytes.is_null() {
        return 0;
    }
    catch_unwind(|| {
        // SAFETY: length is exactly 32 or 65, pointer was checked nonnull,
        // and the caller must provide a live readable allocation as documented.
        let raw = unsafe { slice::from_raw_parts(bytes, length) };
        u8::from(PublicKey::new(algorithm, raw).is_ok())
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(algorithm: u32, bytes: &[u8]) -> bool {
        // SAFETY: slice owns a readable buffer of the supplied length.
        unsafe { yhes_wire_public_key_is_valid(algorithm, bytes.as_ptr(), bytes.len()) == 1 }
    }
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn rejects_invalid_abi_inputs_without_reading() {
        // SAFETY: all combinations are rejected before attempting pointer reads.
        unsafe {
            assert_eq!(yhes_wire_public_key_is_valid(1, std::ptr::null(), 32), 0);
            assert_eq!(yhes_wire_public_key_is_valid(2, std::ptr::null(), 65), 0);
            assert_eq!(
                yhes_wire_public_key_is_valid(99, std::ptr::null(), usize::MAX),
                0
            );
            assert_eq!(
                yhes_wire_public_key_is_valid(1, std::ptr::null(), usize::MAX),
                0
            );
        }
        assert!(!valid(1, &[0; 31]));
        assert!(!valid(2, &[0; 64]));
        assert!(!valid(3, &[0; 32]));
    }
    #[test]
    fn ed25519_accepts_rfc8032_and_rejects_weak_keys() {
        assert!(valid(
            1,
            &hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        ));
        assert!(!valid(1, &[0; 32]));
        let mut off_curve = [0; 32];
        off_curve[0] = 2;
        assert!(!valid(1, &off_curve));
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(!valid(1, &identity));
        assert!(!valid(
            1,
            &hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        ));
    }
    #[test]
    fn p256_accepts_generator_and_rejects_invalid_points() {
        assert!(valid(2, &hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")));
        assert!(!valid(2, &[0; 65]));
        assert!(!valid(2, &[4; 65]));
        assert!(!valid(2, &[3; 33]));
    }
}
