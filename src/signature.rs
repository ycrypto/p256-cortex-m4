//! Implementations of the `signature` traits.

pub use elliptic_curve::consts::U32;
pub use rand_core::{CryptoRng, RngCore};
pub use signature::{digest::{Digest, FixedOutput}, Result};

use crate::{PublicKey, SecretKey};

#[derive(Clone, Copy, Debug)]
/// "Bag of bytes" form of signature, as required by [`signature::Signature`] trait.
// NB: All ways of constructing this should ensure it's formally valid
// TODO: should we store (r, s), which we have to verify anyway?
// This is a trade-off between space efficiency and runtime efficiency.
pub struct Signature([u8; 64]);

impl From<crate::Signature> for Signature {
    /// Converts an internal signature to a bag-of-bytes signature
    fn from(signature: crate::Signature) -> Signature {
        Signature(signature.to_untagged_bytes())
    }
}

impl From<Signature> for crate::Signature {
    /// Converts a bag-of-bytes signature to an internal signature
    fn from(signature: Signature) -> crate::Signature {
        crate::Signature::from_untagged_bytes(&signature.0)
            .expect("valid signature")
    }
}


impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        crate::Signature::from_untagged_bytes(bytes)
            .map_err(|_| signature::Error::new())
            .map(|sig| sig.into())
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }
}

impl signature::Verifier<Signature> for PublicKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        self.verify(msg, &(*signature).into())
            .then(|| ())
            .ok_or_else(signature::Error::new)
    }
}

impl signature::RandomizedSigner<Signature> for SecretKey {
    fn try_sign_with_rng(&self, rng: impl CryptoRng + RngCore, msg: &[u8]) -> Result<Signature> {
        Ok(self.sign(msg, rng).into())
    }
}

impl<D> signature::RandomizedDigestSigner<D, Signature> for SecretKey
where
    D: Digest + FixedOutput<OutputSize = U32>,
{
    fn try_sign_digest_with_rng(&self, rng: impl CryptoRng + RngCore, digest: D) -> Result<Signature> {
        Ok(self.sign_prehashed(digest.finalize_fixed().into(), rng).into())
    }
}
