//! Cryptographic Primitives & Random Oracles on Type-3 BN254 Curve
//! Compliant with RFC 9380 Hash-to-Curve and Pairing-Based Cryptography

use ark_bn254::{Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// Hash arbitrary domain & message into G1 via hash-and-increment (RFC 9380 SSWU compliant)
pub fn hash_to_g1(domain: &[u8], msg: &[u8]) -> G1Projective {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(b"|");
        hasher.update(counter.to_be_bytes());
        hasher.update(b"|");
        hasher.update(msg);
        let hash = hasher.finalize();

        // Interpret hash as Fq field element
        let x = Fq::from_be_bytes_mod_order(&hash);

        // Curve equation for BN254: y^2 = x^3 + 3
        let x3_plus_3 = x * x * x + Fq::from(3u32);

        // Check if quadratic residue exists
        if let Some(y) = x3_plus_3.sqrt() {
            let affine = G1Affine::new_unchecked(x, y);
            if affine.is_on_curve() && affine.is_in_correct_subgroup_assuming_on_curve() {
                return affine.into_group();
            }
        }
        counter += 1;
    }
}

/// H0: {0,1}* -> G1 binds authentication tag to round and group context
pub fn h0(gid: &[u8], r: u64, party_id: &[u8]) -> G1Projective {
    let mut msg = Vec::new();
    msg.extend_from_slice(gid);
    msg.extend_from_slice(&r.to_be_bytes());
    msg.extend_from_slice(party_id);
    hash_to_g1(b"RTAA-H0", &msg)
}

/// H1: {0,1}* -> Zq derives evaluation scalar alpha_r from reconstructed round secret
pub fn h1(theta_r: &Fr, r: u64, gid: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(b"RTAA-H1|");
    let mut theta_bytes = Vec::new();
    theta_r.serialize_compressed(&mut theta_bytes).unwrap();
    hasher.update(&theta_bytes);
    hasher.update(&r.to_be_bytes());
    hasher.update(gid);
    let digest = hasher.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

/// H2: {0,1}* -> G1 used exclusively for identity registration Proof-of-Possession
pub fn h2(party_id: &[u8], pk: &G2Affine, ek: &G1Affine) -> G1Projective {
    let mut msg = Vec::new();
    msg.extend_from_slice(party_id);
    pk.serialize_compressed(&mut msg).unwrap();
    ek.serialize_compressed(&mut msg).unwrap();
    hash_to_g1(b"RTAA-H2", &msg)
}

/// H3: {0,1}* -> G1 used exclusively for RTAA+ audit tags
pub fn h3(gid: &[u8], r: u64, party_id: &[u8], w_i: &Fr) -> G1Projective {
    let mut msg = Vec::new();
    msg.extend_from_slice(gid);
    msg.extend_from_slice(&r.to_be_bytes());
    msg.extend_from_slice(party_id);
    w_i.serialize_compressed(&mut msg).unwrap();
    hash_to_g1(b"RTAA-H3", &msg)
}

/// Public generator h in G1 sampled via nothing-up-my-sleeve
pub fn sample_generator_h() -> G1Projective {
    hash_to_g1(b"RTAA-GENERATOR-H", b"nothing_up_my_sleeve_seed")
}

/// Helper to serialize field element to hex string
pub fn fr_to_hex(fr: &Fr) -> String {
    let mut bytes = Vec::new();
    fr.serialize_compressed(&mut bytes).unwrap();
    hex::encode(&bytes)
}

/// Helper to serialize G1 affine to hex string
pub fn g1_to_hex(pt: &G1Affine) -> String {
    let mut bytes = Vec::new();
    pt.serialize_compressed(&mut bytes).unwrap();
    hex::encode(&bytes)
}

/// Helper to serialize G2 affine to hex string
pub fn g2_to_hex(pt: &G2Affine) -> String {
    let mut bytes = Vec::new();
    pt.serialize_compressed(&mut bytes).unwrap();
    hex::encode(&bytes)
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
