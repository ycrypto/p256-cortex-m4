use p256_cortex_m4::{PublicKey, SecretKey, Signature};

// message hash
const HASH: [u8; 32] = [
    0x44, 0xac, 0xf6, 0xb7, 0xe3, 0x6c, 0x13, 0x42, 0xc2, 0xc5, 0x89, 0x72, 0x04, 0xfe, 0x09, 0x50,
    0x4e, 0x1e, 0x2e, 0xfb, 0x1a, 0x90, 0x03, 0x77, 0xdb, 0xc4, 0xe7, 0xa6, 0xa1, 0x33, 0xec, 0x56,
];

const R: [u8; 32] = [
    0xf3, 0xac, 0x80, 0x61, 0xb5, 0x14, 0x79, 0x5b, 0x88, 0x43, 0xe3, 0xd6, 0x62, 0x95, 0x27, 0xed,
    0x2a, 0xfd, 0x6b, 0x1f, 0x6a, 0x55, 0x5a, 0x7a, 0xca, 0xbb, 0x5e, 0x6f, 0x79, 0xc8, 0xc2, 0xac,
];
const S: [u8; 32] = [
    0x8b, 0xf7, 0x78, 0x19, 0xca, 0x05, 0xa6, 0xb2, 0x78, 0x6c, 0x76, 0x26, 0x2b, 0xf7, 0x37, 0x1c,
    0xef, 0x97, 0xb2, 0x18, 0xe9, 0x6f, 0x17, 0x5a, 0x3c, 0xcd, 0xda, 0x2a, 0xcc, 0x05, 0x89, 0x03,
];

// a fixed nonce is used for a deterministic R and S
const NOT_NONCE: [u8; 32] = [
    0x94, 0xa1, 0xbb, 0xb1, 0x4b, 0x90, 0x6a, 0x61, 0xa2, 0x80, 0xf2, 0x45, 0xf9, 0xe9, 0x3c, 0x7f,
    0x3b, 0x4a, 0x62, 0x47, 0x82, 0x4f, 0x5d, 0x33, 0xb9, 0x67, 0x07, 0x87, 0x64, 0x2a, 0x68, 0xde,
];

#[derive(Default)]
struct NotRng {}

impl rand_core::RngCore for NotRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&NOT_NONCE);
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}

impl rand_core::CryptoRng for NotRng {}

#[test]
fn sign() {
    const PRIVATE_KEY: [u8; 32] = [
        0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58, 0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77,
        0x1a, 0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac, 0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72,
        0xb4, 0x64,
    ];

    let key = SecretKey::from_bytes(PRIVATE_KEY).unwrap();
    let signature = key.sign_prehashed(HASH, NotRng::default());

    assert_eq!(signature.r(), R);
    assert_eq!(signature.s(), S);
}

#[test]
fn verify() {
    const PUBLIC_KEY: [u8; 64] = [
        0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f,
        0xcc, 0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71,
        0xbf, 0x83, 0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e,
        0x61, 0x13, 0xe0, 0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c,
        0xa8, 0x9a, 0x4c, 0xa9,
    ];

    let key = PublicKey::from_untagged_bytes(&PUBLIC_KEY).unwrap();

    let mut signature: [u8; 64] = [0; 64];
    signature[..32].copy_from_slice(&R);
    signature[32..].copy_from_slice(&S);
    let signature = Signature::from_untagged_bytes(&signature).unwrap();
    let authentic = key.verify_prehashed(HASH, &signature);
    assert!(authentic);
}
