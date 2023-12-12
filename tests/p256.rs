use hex_literal::hex;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "prehash")]
use p256::ecdsa::signature::Verifier;
use rand::thread_rng;

const fn public_bytes_to_sec1(pubkey: &[u8; 64]) -> [u8; 65] {
    let mut buf = [0x04; 65];
    let mut i = 0;
    while i < 64 {
        buf[i + 1] = pubkey[i];
        i += 1;
    }
    buf
}

const SECTRET_KEY_1: [u8; 32] =
    hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");
const PUBLIC_KEY_1: [u8; 64] = hex!("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9");
const PUBLIC_KEY_1_SEC1: [u8; 65] = public_bytes_to_sec1(&PUBLIC_KEY_1);

const SECTRET_KEY_2: [u8; 32] =
    hex!("fb5469bfaac8eb74c32905fc92b50dba9f6660cdcd42df9e120ba0c6bbe00409");
const PUBLIC_KEY_2: [u8; 64] = hex!("d717e98cbb77382563fac7530c4c10d6d608af29837c051e3c191243b1c290df036d562ded21bb3753ad134660d9eb13a66c175e13f4555659916e78316de430");
const PUBLIC_KEY_2_SEC1: [u8; 65] = public_bytes_to_sec1(&PUBLIC_KEY_2);

#[test]
fn keys() {
    let secret_key_1 = p256::SecretKey::from_bytes((&SECTRET_KEY_1).into()).unwrap();
    let public_key_1 = secret_key_1.public_key();
    assert_eq!(*public_key_1.to_sec1_bytes(), PUBLIC_KEY_1_SEC1);
    let secret_key_2 = p256::SecretKey::from_bytes((&SECTRET_KEY_2).into()).unwrap();
    let public_key_2 = secret_key_2.public_key();
    assert_eq!(*public_key_2.to_sec1_bytes(), PUBLIC_KEY_2_SEC1);

    let secret_key_1 = p256_cortex_m4::SecretKey::from_bytes(SECTRET_KEY_1).unwrap();
    let public_key_1 = secret_key_1.public_key();
    assert_eq!(public_key_1.to_uncompressed_sec1_bytes(), PUBLIC_KEY_1_SEC1);
    let secret_key_2 = p256_cortex_m4::SecretKey::from_bytes(SECTRET_KEY_2).unwrap();
    let public_key_2 = secret_key_2.public_key();
    assert_eq!(public_key_2.to_uncompressed_sec1_bytes(), PUBLIC_KEY_2_SEC1);
}

#[test]
fn ecdh() {
    let secret_key_1 = p256::SecretKey::from_bytes((&SECTRET_KEY_1).into()).unwrap();
    let public_key_2 = p256::PublicKey::from_sec1_bytes(&PUBLIC_KEY_2_SEC1).unwrap();
    let shared_secret_ref = elliptic_curve::ecdh::diffie_hellman(
        secret_key_1.to_nonzero_scalar(),
        public_key_2.as_affine(),
    );

    let secret_key_1 = p256_cortex_m4::SecretKey::from_bytes(SECTRET_KEY_1).unwrap();
    let public_key_1 = p256_cortex_m4::PublicKey::from_untagged_bytes(&PUBLIC_KEY_1).unwrap();
    let secret_key_2 = p256_cortex_m4::SecretKey::from_bytes(SECTRET_KEY_2).unwrap();
    let public_key_2 = p256_cortex_m4::PublicKey::from_untagged_bytes(&PUBLIC_KEY_2).unwrap();

    let shared_1 = secret_key_1.agree(&public_key_2);
    let shared_2 = secret_key_2.agree(&public_key_1);
    assert_eq!(
        &shared_secret_ref.raw_secret_bytes()[..],
        shared_1.as_bytes()
    );
    assert_eq!(
        &shared_secret_ref.raw_secret_bytes()[..],
        shared_2.as_bytes()
    );
}

#[test]
fn sign() {
    let secret_key_ref = p256::SecretKey::from_bytes((&SECTRET_KEY_1).into()).unwrap();
    let public_key_ref: p256::ecdsa::VerifyingKey = secret_key_ref.public_key().into();

    let secret_key = p256_cortex_m4::SecretKey::from_bytes(SECTRET_KEY_1).unwrap();
    let public_key = p256_cortex_m4::PublicKey::from_untagged_bytes(&PUBLIC_KEY_1).unwrap();

    const HASH: [u8; 32] = hex!("b4d508d432ad5de819c3ffeb92e050b76320f17a96535600716b1374829f60ef");

    let signed_prehash = secret_key.sign_prehashed(&HASH, &mut thread_rng());
    assert!(public_key.verify_prehashed(&HASH, &signed_prehash));
    assert!(public_key_ref
        .verify_prehash(
            &HASH,
            &p256::ecdsa::Signature::from_bytes(&signed_prehash.to_untagged_bytes().into())
                .unwrap()
        )
        .is_ok());
    #[cfg(feature = "prehash")]
    {
        const DATA: &[u8] = b"Data to sign";
        let signed = secret_key.sign(&DATA, &mut thread_rng());
        assert!(public_key.verify(&DATA, &signed));
        assert!(public_key.verify_prehashed(&HASH, &signed));
        assert!(public_key_ref
            .verify(
                &DATA,
                &p256::ecdsa::Signature::from_bytes(&signed.to_untagged_bytes().into()).unwrap()
            )
            .is_ok());
        assert!(public_key_ref
            .verify_prehash(
                &HASH,
                &p256::ecdsa::Signature::from_bytes(&signed.to_untagged_bytes().into()).unwrap()
            )
            .is_ok());
    }
}
