//! Rotating Threshold Aggregate Authenticators (RTAA and RTAA+) Protocol Engine
//! Based on: "Rotating Threshold Aggregate Authenticators: Construction and Non-Frameability"
//! Cryptographic Engine: Type-3 Asymmetric Pairing on BN254 Curve (arkworks)

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, UniformRand, Zero};
use rand::thread_rng;

use crate::crypto::{h0, h1, h2, h3, sample_generator_h};
use crate::packet::NetworkAuthPacket;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PartyState {
    pub id: Vec<u8>,
    pub index: usize,
    pub sk: Fr,             // Signing secret key in Zq
    pub pk: G2Affine,       // Signing public key in G2
    pub ek: Fr,             // Encryption secret key in Zq
    pub ek_pub: G1Affine,   // Encryption public key in G1
    pub sigma: G1Affine,    // Proof of identity (Eq. 1)
}

#[derive(Clone, Debug)]
pub struct AuthReport {
    pub id: Vec<u8>,
    pub pk: G2Affine,
    pub w_i: Fr,
    pub tau_i: G1Affine,
    pub rho_i: Option<G1Affine>, // RTAA+ audit tag
    pub m_i: Vec<Fr>,
}

impl AuthReport {
    pub fn from_packet(pkt: &NetworkAuthPacket) -> Self {
        Self {
            id: pkt.source_node_id.clone(),
            pk: pkt.public_key,
            w_i: pkt.claimed_weight,
            tau_i: pkt.base_tag,
            rho_i: pkt.audit_tag,
            m_i: pkt.payload_vector.clone(),
        }
    }
}

pub struct AggregateResult {
    pub m_agg: Vec<Fr>,
    pub tau_agg: G1Affine,
    pub w_agg: Fr,
    pub reports: Vec<AuthReport>,
}

#[allow(dead_code)]
pub struct RTAAProtocol {
    pub t: usize,
    pub n: usize,
    pub k: usize,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub h: G1Projective,
}

impl RTAAProtocol {
    pub fn new(t: usize, n: usize, k: usize) -> Self {
        Self {
            t,
            n,
            k,
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
            h: sample_generator_h(),
        }
    }

    /// Step 1: Setup & Identity Registration (Eq. 1)
    pub fn setup_party(&self, id: &[u8], index: usize) -> PartyState {
        let mut rng = thread_rng();
        let sk = Fr::rand(&mut rng);
        let ek = Fr::rand(&mut rng);
        let pk = (self.g2 * sk).into_affine();
        let ek_pub = (self.g1 * ek).into_affine();

        let h2_val = h2(id, &pk, &ek_pub);
        let sigma = (h2_val * sk).into_affine();

        // Verify Equation (1): e(sigma, g2) == e(H2(...), PK)
        let lhs = Bn254::pairing(sigma, self.g2.into_affine());
        let rhs = Bn254::pairing(h2_val.into_affine(), pk);
        assert_eq!(lhs, rhs, "Proof-of-Possession failed for party registration");

        PartyState {
            id: id.to_vec(),
            index,
            sk,
            pk,
            ek,
            ek_pub,
            sigma,
        }
    }

    /// Step 2: Threshold Key Generation (Pedersen VSS, Equations 2-5)
    pub fn thresh_key_gen(
        &self,
        gid: &[u8],
        r: u64,
        ell: usize,
        parties: &[PartyState],
    ) -> (Fr, Vec<G1Affine>) {
        let mut rng = thread_rng();
        let mut dealer_poly_f = Vec::new();
        let mut dealer_poly_f_tilde = Vec::new();
        let mut commitments_c = Vec::new();

        // 1. Each co-dealer samples degree-(t-1) polynomials and publishes Pedersen commitments
        for _ in 0..ell {
            let a_d: Vec<Fr> = (0..self.t).map(|_| Fr::rand(&mut rng)).collect();
            let a_tilde_d: Vec<Fr> = (0..self.t).map(|_| Fr::rand(&mut rng)).collect();

            let mut comm_d = Vec::new();
            for u in 0..self.t {
                let term1 = self.g1 * a_d[u];
                let term2 = self.h * a_tilde_d[u];
                comm_d.append(&mut vec![(term1 + term2).into_affine()]);
            }
            dealer_poly_f.push(a_d);
            dealer_poly_f_tilde.push(a_tilde_d);
            commitments_c.push(comm_d);
        }

        // 2. Compute and verify shares for each party (Eq. 3)
        let mut combined_shares = Vec::new();
        for party in parties {
            let idx = Fr::from(party.index as u64);
            let mut sum_s_i = Fr::zero();

            for d in 0..ell {
                let mut s_di = Fr::zero();
                let mut s_tilde_di = Fr::zero();
                let mut idx_pow = Fr::from(1u32);

                for u in 0..self.t {
                    s_di += dealer_poly_f[d][u] * idx_pow;
                    s_tilde_di += dealer_poly_f_tilde[d][u] * idx_pow;
                    idx_pow *= idx;
                }

                // Check Eq. (3): g1^{s_di} * h^{\tilde{s}_di} == prod_{u=0}^{t-1} (C_u^(d))^{idx^u}
                let lhs = self.g1 * s_di + self.h * s_tilde_di;
                let mut rhs = G1Projective::zero();
                let mut idx_u = Fr::from(1u32);
                for u in 0..self.t {
                    rhs += commitments_c[d][u] * idx_u;
                    idx_u *= idx;
                }
                assert_eq!(lhs, rhs, "Invalid Pedersen share from co-dealer");
                sum_s_i += s_di;
            }
            combined_shares.push(sum_s_i);
        }

        // 3. Reconstruct round secret theta_r using Lagrange interpolation over t parties
        let mut theta_r = Fr::zero();
        for i in 0..self.t {
            let xi = Fr::from(parties[i].index as u64);
            let mut num = Fr::from(1u32);
            let mut den = Fr::from(1u32);
            for j in 0..self.t {
                if i != j {
                    let xj = Fr::from(parties[j].index as u64);
                    num *= -xj;
                    den *= xi - xj;
                }
            }
            let lagrange_coeff = num * den.inverse().unwrap();
            theta_r += combined_shares[i] * lagrange_coeff;
        }

        // 4. Derive round evaluation scalar alpha_r (Eq. 4)
        let alpha_r = h1(&theta_r, r, gid);

        // 5. Publish power commitments Gamma_j = g1^{alpha_r^j} (Eq. 5)
        let mut power_commitments = Vec::new();
        let mut curr_power = alpha_r;
        for _ in 1..=self.k {
            power_commitments.push((self.g1 * curr_power).into_affine());
            curr_power *= alpha_r;
        }

        (alpha_r, power_commitments)
    }

    /// Step 3: Authentication (Equations 6, 7 & 17)
    pub fn auth(
        &self,
        gid: &[u8],
        r: u64,
        party: &PartyState,
        m_i: &[Fr],
        alpha_r: Fr,
        include_audit: bool,
    ) -> AuthReport {
        assert_eq!(m_i.len(), self.k);

        // Compute algebraic weight w^(i) = sum_{j=1}^k m_j * alpha_r^j mod q
        let mut w_i = Fr::zero();
        let mut alpha_pow = alpha_r;
        for j in 0..self.k {
            w_i += m_i[j] * alpha_pow;
            alpha_pow *= alpha_r;
        }

        // tau^(i) = (H0(GID || r || ID^(i)) + g1^{w^(i)})^{sk^(i)}
        let h0_val = h0(gid, r, &party.id);
        let g1_w = self.g1 * w_i;
        let base = h0_val + g1_w;
        let tau_i = (base * party.sk).into_affine();

        // RTAA+ audit tag: rho^(i) = H3(GID || r || ID^(i) || w^(i))^{sk^(i)}
        let rho_i = if include_audit {
            let h3_val = h3(gid, r, &party.id, &w_i);
            Some((h3_val * party.sk).into_affine())
        } else {
            None
        };

        AuthReport {
            id: party.id.clone(),
            pk: party.pk,
            w_i,
            tau_i,
            rho_i,
            m_i: m_i.to_vec(),
        }
    }

    /// Step 4: Untrusted Aggregation (Equation 8)
    pub fn aggregate(&self, reports: &[AuthReport]) -> AggregateResult {
        assert!(!reports.is_empty());
        let k = self.k;

        // tau_agg = sum tau_i in G1
        let mut tau_agg_proj = G1Projective::zero();
        for rep in reports {
            tau_agg_proj += rep.tau_i;
        }
        let tau_agg = tau_agg_proj.into_affine();

        // M_agg = sum M_i in Zq^k
        let mut m_agg = vec![Fr::zero(); k];
        for rep in reports {
            for j in 0..k {
                m_agg[j] += rep.m_i[j];
            }
        }

        // w_agg = sum w_i in Zq
        let mut w_agg = Fr::zero();
        for rep in reports {
            w_agg += rep.w_i;
        }

        AggregateResult {
            m_agg,
            tau_agg,
            w_agg,
            reports: reports.to_vec(),
        }
    }

    /// Step 5: Verification (Equations 10-13)
    pub fn verify(
        &self,
        gid: &[u8],
        r: u64,
        agg_res: &AggregateResult,
        power_commitments: &[G1Affine],
    ) -> bool {
        let reports = &agg_res.reports;

        // Check 1: Well-formedness check (distinct IDs)
        for i in 0..reports.len() {
            for j in (i + 1)..reports.len() {
                if reports[i].id == reports[j].id {
                    return false;
                }
            }
        }

        // Check 2: Consistency check (Gamma* == g1^{w_agg})
        let mut gamma_star = G1Projective::zero();
        for j in 0..self.k {
            gamma_star += power_commitments[j] * agg_res.m_agg[j];
        }
        let g1_wagg = self.g1 * agg_res.w_agg;
        if gamma_star != g1_wagg {
            return false;
        }

        // Check 3: Authentication check (Eq. 13)
        // LHS: e(tau_agg, g2)
        let lhs = Bn254::pairing(agg_res.tau_agg, self.g2.into_affine());

        // RHS: prod_{i in S} e(H0(...) + g1^{w_i}, PK_i)
        let mut rhs = PairingOutput::<Bn254>::zero();
        for rep in reports {
            let h0_val = h0(gid, r, &rep.id);
            let g1_wi = self.g1 * rep.w_i;
            let bracket = (h0_val + g1_wi).into_affine();
            let pair_i = Bn254::pairing(bracket, rep.pk);
            rhs += pair_i;
        }

        lhs == rhs
    }

    /// Step 6: Base RTAA Judge (Algorithm 1) via Bisection Tree
    pub fn judge_base(&self, gid: &[u8], r: u64, reports: &[AuthReport]) -> Vec<u8> {
        if reports.len() == 1 {
            return reports[0].id.clone();
        }

        let mid = reports.len() / 2;
        let s1 = &reports[..mid];
        let s2 = &reports[mid..];

        // Test sub-aggregate S1
        let mut tau_s1 = G1Projective::zero();
        for rep in s1 {
            tau_s1 += rep.tau_i;
        }

        let lhs = Bn254::pairing(tau_s1.into_affine(), self.g2.into_affine());
        let mut rhs = PairingOutput::<Bn254>::zero();
        for rep in s1 {
            let h0_val = h0(gid, r, &rep.id);
            let g1_wi = self.g1 * rep.w_i;
            let bracket = (h0_val + g1_wi).into_affine();
            rhs += Bn254::pairing(bracket, rep.pk);
        }

        if lhs != rhs {
            self.judge_base(gid, r, s1)
        } else {
            self.judge_base(gid, r, s2)
        }
    }

    /// Step 6: RTAA+ Judge+ (Section 6.4) with O(1) Audit Check
    pub fn judge_plus(&self, gid: &[u8], r: u64, reports: &[AuthReport]) -> (Vec<u8>, String) {
        // Step 1: Check non-aggregated audit tag rho^(i) for each party (Eq. 18)
        for rep in reports {
            if let Some(rho_i) = rep.rho_i {
                let h3_val = h3(gid, r, &rep.id, &rep.w_i).into_affine();
                let lhs = Bn254::pairing(rho_i, self.g2.into_affine());
                let rhs = Bn254::pairing(h3_val, rep.pk);
                if lhs != rhs {
                    return (
                        rep.id.clone(),
                        "Audit check failed: Tampered weight / forged tag (Eq. 18)".to_string(),
                    );
                }
            } else {
                return (rep.id.clone(), "Missing audit tag rho".to_string());
            }
        }

        // Step 2: Fallback to bisection
        let accused = self.judge_base(gid, r, reports);
        (accused, "Bisection blame fallback".to_string())
    }
}
