use core::{convert::TryInto, mem::MaybeUninit};

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};
#[cfg(feature = "prehash")]
use crate::sha256;

/// NIST P-256 secret key.
///
/// The internal representation is as little-endian (native) words.
#[derive(Clone, Zeroize)]
pub struct SecretKey([u32; 8]);

/// NIST P-256 public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    x: [u32; 8],
    y: [u32; 8],
}

/// NIST P-256 keypair.
#[derive(Clone)]
pub struct Keypair {
    /// Public key of the keypair
    pub public: PublicKey,
    /// Secret key of the keypair
    pub secret: SecretKey,
}

/// NIST P-256 signature.
///
/// TODO: It seems we might be able to use the `p256` machinery for this,
/// instead of reimplementing it ourselves.
#[derive(Clone, Debug)]
pub struct Signature {
    r: [u32; 8],
    s: [u32; 8],
}

/// Outcome of ECDH key agreement.
///
/// The x-coordinate of the multiplication of a secret key and a public key,
/// represented as big-endian integer.
#[derive(Clone, Zeroize)]
pub struct SharedSecret([u8; 32]);

impl Keypair {
    /// Generate a random `Keypair`.
    ///
    /// The implementation uses rejection sampling.
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        let mut keypair = Keypair {
            public: PublicKey {
                x: [0u32; 8],
                y: [0u32; 8],
            },
            secret: SecretKey([0u32; 8]),
        };

        let mut rng = rng;
        loop {
            rng.fill_bytes(unsafe { core::mem::transmute::<&mut [u32; 8], &mut [u8; 32]>(&mut keypair.secret.0) });
            let valid = unsafe { p256_cortex_m4_sys::p256_keygen(
                &mut keypair.public.x[0] as *mut _,
                &mut keypair.public.y[0] as _,
                &keypair.secret.0[0] as _,
            ) };
            if valid {
                return keypair;
            }
        }
    }
}

impl SecretKey {
    /// Generate a random `SecretKey`.
    ///
    /// The implementation uses rejection sampling.
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        let mut secret = SecretKey([0u32; 8]);
        let mut rng = rng;
        loop {
            rng.fill_bytes(unsafe { core::mem::transmute::<&mut [u32; 8], &mut [u8; 32]>(&mut secret.0) });
            let valid = unsafe { p256_cortex_m4_sys::P256_check_range_n(
                &secret.0[0] as *const u32,
            ) };
            if valid {
                return secret
            }
        }
    }

    /// Verifies that there are 32 bytes that correspond to a big-endian integer in the range 1..=n-1.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(Error);
        }

        let mut secret = SecretKey([0u32; 8]);
        unsafe { p256_cortex_m4_sys::p256_convert_endianness(
            &mut secret.0[0] as *mut u32 as *mut _,
            &bytes[0] as *const u8 as *const _,
            32,
        ) };

        if !unsafe { p256_cortex_m4_sys::P256_check_range_n(
            &secret.0[0] as *const u32,
        ) } {
            return Err(Error);
        }
        Ok(secret)
    }

    // /// Verifies that there are 8 words that correspond to a little-endian integer in the range 1..=n-1.
    // pub fn from_words(bytes: impl AsRef<[u32]>) -> Option<Self> {
    //     if bytes.as_ref().len() != 8 {
    //         return None
    //     }
    //     if !unsafe { p256_cortex_m4_sys::P256_check_range_n(
    //         &bytes.as_ref()[0] as *const u32,
    //     ) } {
    //         return None
    //     }
    //     Some(Self(bytes.as_ref().try_into().ok()?))
    // }

    #[allow(unused_unsafe)]
    /// Convert endianness to obtain the big-endian representation of the secret scalar as 32 bytes.
    ///
    /// "unsafe" because the caller is responsible for keeping the value secret.
    pub unsafe fn to_bytes(&self) -> [u8; 32] {
        let mut big_endian = [0u8; 32];
        unsafe { p256_cortex_m4_sys::p256_convert_endianness(
            &mut big_endian[0] as *mut u8 as *mut _,
            &self.0[0] as *const u32 as *const _,
            32,
        ) };
        big_endian
    }

    /// Calculate associated public key.
    pub fn public_key(&self) -> PublicKey {
        let mut public = PublicKey {
            x: [0u32; 8],
            y: [0u32; 8],
        };
        // NB: We already know we are a valid secret key
        unsafe { p256_cortex_m4_sys::p256_keygen(
            &mut public.x[0] as *mut _,
            &mut public.y[0] as _,
            &self.0[0] as _,
        ) };
        public
    }

    /// Non-deterministic signature on message assumed to be hashed, if needed.
    ///
    /// Internally, draws 256-bit `k` repeatedly, until signing succeeds.
    pub fn sign_prehashed(&self, prehashed_message: &[u8], rng: impl CryptoRng + RngCore) -> Signature {
        let mut signature = Signature {
            r: [0u32; 8],
            s: [0u32; 8],
        };
        let mut k = Zeroizing::<[u32; 8]>::new([0u32; 8]);
        let mut rng = rng;
        loop {
            rng.fill_bytes(unsafe { core::mem::transmute::<&mut [u32; 8], &mut [u8; 32]>(&mut k) });
            if unsafe { p256_cortex_m4_sys::p256_sign(
                &mut signature.r[0] as *mut u32,
                &mut signature.s[0] as *mut u32,
                &prehashed_message[0] as *const u8,
                prehashed_message.len() as u32,
                &self.0 as *const u32,
                &k[0] as *const u32,
            ) } {
                return signature;
            }
        }
    }

    #[cfg(feature = "prehash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "prehash")))]
    /// Non-deterministic signature on message, which is hashed with SHA-256 first.
    pub fn sign(&self, message: &[u8], rng: impl CryptoRng + RngCore) -> Signature {
        let prehashed_message = sha256(message);
        self.sign_prehashed(prehashed_message.as_ref(), rng)
    }

    /// ECDH key agreement.
    pub fn agree(&self, other: &PublicKey) -> SharedSecret {
        let mut shared = SharedSecret([0u8; 32]);
        // NB: By construction, `other` is a valid public key, so we do not need
        // to check the return value.
        unsafe { p256_cortex_m4_sys::p256_ecdh_calc_shared_secret(
            &mut shared.0[0] as *mut _,
            &self.0[0] as *const _,
            &other.x[0] as *const _,
            &other.y[0] as *const _,
        ) };
        shared
    }
}

impl PublicKey {
    /// Decode assuming `bytes` is x-coordinate then y-coordinate, both big-endian 32B arrays.
    ///
    /// In other words, the uncompressed SEC1 format, without the leading 0x04 byte tag.
    pub fn from_untagged_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error);
        }
        let mut sec1_bytes = [4u8; 65];
        sec1_bytes[1..].copy_from_slice(bytes);
        Self::from_sec1_bytes(&sec1_bytes)
    }

    /// Decode `PublicKey` (compressed or uncompressed) from the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding in [SEC 1][sec-1] (section 2.3.3)
    ///
    /// This is the left-inverse of both `to_compressed_bytes` and `to_uncompressed_bytes`.
    ///
    /// [sec-1]: http://www.secg.org/sec1-v2.pdf
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        // NB: https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#initializing-a-struct-field-by-field
        let mut public = PublicKey {
            x: [0u32; 8],
            y: [0u32; 8],
        };
        if unsafe { p256_cortex_m4_sys::p256_octet_string_to_point(
            &mut public.x[0] as *mut _,
            &mut public.y[0] as *mut _,
            &bytes[0] as *const _,
            bytes.len() as u32,
        ) } {
            return Ok(public)
        } else {
            return Err(Error)
        }
    }

    /// Raw encoding, x-coordinate then y-coordinate.
    pub fn to_untagged_bytes(&self) -> [u8; 64] {
        self.to_uncompressed_sec1_bytes()[1..].try_into().unwrap()
    }

    /// Compressed encoding: `02 || Px` if Py is even and `03 || Px` if Py is odd
    pub fn to_compressed_sec1_bytes(&self) -> [u8; 33] {
        let mut bytes = MaybeUninit::<[u8; 33]>::uninit();
        unsafe {
            p256_cortex_m4_sys::p256_point_to_octet_string_compressed(
                bytes.as_mut_ptr() as *mut _,
                &self.x[0] as *const _,
                &self.y[0] as *const _,
            );
            bytes.assume_init()
        }
    }

    /// Uncompressed encoding: `04 || Px || Py`.
    pub fn to_uncompressed_sec1_bytes(&self) -> [u8; 65] {
        let mut bytes = MaybeUninit::<[u8; 65]>::uninit();
        unsafe {
            p256_cortex_m4_sys::p256_point_to_octet_string_uncompressed(
                bytes.as_mut_ptr() as *mut _,
                &self.x[0] as *const _,
                &self.y[0] as *const _,
            );
            bytes.assume_init()
        }
    }

    /// Big-endian representation of x-coordinate.
    pub fn x(&self) -> [u8; 32] {
        self.to_uncompressed_sec1_bytes()[1..33].try_into().unwrap()
    }

    /// Big-endian representation of x-coordinate.
    pub fn y(&self) -> [u8; 32] {
        self.to_uncompressed_sec1_bytes()[33..].try_into().unwrap()
    }

    /// Verify signature on message assumed to be hashed, if needed.
    pub fn verify_prehashed(&self, prehashed_message: &[u8], signature: &Signature) -> bool {
        unsafe { p256_cortex_m4_sys::p256_verify(
            &self.x[0] as *const u32,
            &self.y[0] as *const u32,
            &prehashed_message[0] as *const u8,
            prehashed_message.len() as u32,
            &signature.r[0] as *const u32,
            &signature.s[0] as *const u32,
        ) }
    }

    /// Verify signature on message, which is hashed with SHA-256 first.
    #[cfg(feature = "prehash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "prehash")))]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let prehashed_message = sha256(message);
        self.verify_prehashed(prehashed_message.as_ref(), signature)
    }
}

impl Signature {
    /// Big-endian representation of r.
    fn r(&self) -> [u8; 32] {
        let mut r = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                r.as_mut_ptr() as *mut u8 as *mut _,
                &self.r[0] as *const u32 as *const _,
                32,
            );
            r.assume_init()
        }
    }

    /// Big-endian representation of s.
    fn s(&self) -> [u8; 32] {
        let mut s = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                s.as_mut_ptr() as *mut u8 as *mut _,
                &self.s[0] as *const u32 as *const _,
                32,
            );
            s.assume_init()
        }
    }

    /// Decode signature as big-endian r, then big-endian s, without framing.
    ///
    /// Necessarily, bytes must be of length 64, and r and s must be integers
    /// in the range 1..=n-1, otherwise decoding fails.
    pub fn from_untagged_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error);
        }

        // NB: https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#initializing-a-struct-field-by-field
        let mut signature = Signature {
            r: [0u32; 8],
            s: [0u32; 8],
        };

        unsafe { p256_cortex_m4_sys::p256_convert_endianness(
            &mut signature.r[0] as *mut u32 as *mut _,
            &bytes[0] as *const u8 as *const _,
            32,
        ) };
        let valid_r = unsafe { p256_cortex_m4_sys::P256_check_range_n(
            &signature.r[0] as *const u32,
        ) };

        unsafe { p256_cortex_m4_sys::p256_convert_endianness(
            &mut signature.s[0] as *mut u32 as *mut _,
            &bytes[32] as *const u8 as *const _,
            32,
        ) };
        let valid_s = unsafe { p256_cortex_m4_sys::P256_check_range_n(
            &signature.r[0] as *const u32,
        ) };

        if valid_r && valid_s {
            Ok(signature)
        } else {
            Err(Error)
        }
    }

    // /// Decode signature from ASN.1 DER
    // #[cfg(feature = "sec1-signatures")]
    // #[cfg_attr(docsrs, doc(cfg(feature = "sec1-signatures")))]
    // pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
    //     todo!();
    // }

    /// Encode signature from big-endian r, then big-endian s, without framing.
    pub fn to_untagged_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r());
        bytes[32..].copy_from_slice(&self.s());
        bytes
    }

    /// Encode signature as ASN.1 DER, returning length.
    ///
    /// This means interpreting signature as a SEQUENCE of (unsigned) INTEGERs, as defined
    /// under the name of `ECDSA-Sig-Value` in [SEC 1][sec-1], section C.5.
    ///
    /// [sec-1]: http://www.secg.org/sec1-v2.pdf
    #[cfg(feature = "sec1-signatures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1-signatures")))]
    pub fn to_sec1_bytes(&self, buffer: &mut [u8; 72]) -> usize {
        let r = self.r();
        let s = self.s();
        let signature  = DerSignature {
            r: der::BigUInt::new(&r).unwrap(),
            s: der::BigUInt::new(&s).unwrap(),
        };

        use der::Encodable;
        let l = signature.encode_to_slice(buffer.as_mut()).unwrap().len();
        l
    }
}

#[cfg(feature = "sec1-signatures")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1-signatures")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, der::Message)]
struct DerSignature<'a> {
    pub r: der::BigUInt<'a, der::consts::U32>,
    pub s: der::BigUInt<'a, der::consts::U32>,
}

impl SharedSecret {
    /// The secret (big-endian x-coordinate)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
