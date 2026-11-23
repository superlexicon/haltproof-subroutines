//! Zero-Trusted-Setup Bulletproofs (`Edwards25519`) Range & Sparse R1CS Guest SDK (`hps_sdk::bulletproofs`).
//!
//! - On `wasm32`: `#![no_std]` zero-allocation wrappers over `env::host_bp_verify_range_u64` and
//!   `env::host_bp_verify_r1cs`, plus fixed-buffer `BpCsBuilder<CAP>` and exact `ℤ_ℓ` scalar math.
//! - On host targets (`cargo test`): full native `Edwards25519` Bulletproofs prover & verifier
//!   matching `lexicon/src/vm/bulletproofs.rs` byte-for-byte.

/// Maximum vector dimension (`n` gates or `m * bit_width` bits) per Bulletproof invocation.
pub const MAX_BP_GENERATORS: usize = 256;

/// Maximum Pedersen witness commitments `V_0 .. V_{k-1}` bound into a single R1CS proof.
pub const MAX_BP_R1CS_VARS: usize = 32;

/// Wire selector tags in the compact sparse R1CS binary format.
pub const WIRE_A_L: u8 = 0;
pub const WIRE_A_R: u8 = 1;
pub const WIRE_A_O: u8 = 2;
pub const WIRE_VAR: u8 = 3;

/// Canonical compressed `H_bp` blinding generator (`hash_to_curve("SLX_BP_H_BLIND_V1")`).
pub const BP_H_BLIND_BYTES: [u8; 32] = [
    0xe0, 0xd1, 0x71, 0x2b, 0x6b, 0xdf, 0x25, 0x29,
    0x21, 0x68, 0xe8, 0x35, 0xaf, 0x49, 0x33, 0xc5,
    0xa7, 0xde, 0xba, 0x27, 0x9d, 0xd5, 0x79, 0x71,
    0xd4, 0x1e, 0xd8, 0x1b, 0xea, 0x17, 0xbd, 0x8b,
];

/// Prime subgroup order `ℓ = 2^252 + 27742317777372353535851937790883648493` in 4 little-endian `u64` limbs.
const ORDER_L_LIMBS: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

#[cfg(target_arch = "wasm32")]
mod sys {
    #[link(wasm_import_module = "env")]
    extern "C" {
        pub fn host_bp_verify_range_u64(
            commits_ptr: i32,
            count: i32,
            bit_width: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_ptr: i32,
            proof_len: i32,
        ) -> i32;

        pub fn host_bp_verify_r1cs(
            cs_ptr: i32,
            cs_len: i32,
            commits_ptr: i32,
            commit_cnt: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_ptr: i32,
            proof_len: i32,
        ) -> i32;
    }
}

/// Verifies an aggregated Bulletproof that `commits` (`m` 32-byte Pedersen commitments
/// `V_j = v_j * B + gamma_j * H_bp`) all satisfy `v_j ∈ [0, 2^bit_width)`.
pub fn verify_range_u64(
    commits: &[[u8; 32]],
    bit_width: usize,
    ctx: &[u8],
    proof: &[u8],
) -> bool {
    if commits.is_empty() || proof.is_empty() {
        return false;
    }
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_bp_verify_range_u64(
            commits.as_ptr() as i32,
            commits.len() as i32,
            bit_width as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof.as_ptr() as i32,
            proof.len() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_bp::verify_range_u64_batch(commits, bit_width, ctx, proof)
    }
}

/// Verifies a zero-trusted-setup Bulletproofs R1CS proof against `cs_bytes` and `commits` (`V_0..V_{k-1}`).
pub fn verify_r1cs(
    cs_bytes: &[u8],
    commits: &[[u8; 32]],
    ctx: &[u8],
    proof: &[u8],
) -> bool {
    if cs_bytes.len() < 6 || proof.is_empty() || commits.len() > MAX_BP_R1CS_VARS {
        return false;
    }
    #[cfg(target_arch = "wasm32")]
    unsafe {
        let commits_ptr = if commits.is_empty() {
            0i32
        } else {
            commits.as_ptr() as i32
        };
        sys::host_bp_verify_r1cs(
            cs_bytes.as_ptr() as i32,
            cs_bytes.len() as i32,
            commits_ptr,
            commits.len() as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof.as_ptr() as i32,
            proof.len() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_bp::verify_r1cs(cs_bytes, commits, ctx, proof)
    }
}

// ---------------------------------------------------------------------------
// `#![no_std]` Exact `ℤ_ℓ` Scalar Helpers (Little-Endian 32-Byte Canonical Scalars)
// ---------------------------------------------------------------------------

#[inline]
fn limbs_from_le32(b: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
    ]
}

#[inline]
fn limbs_to_le32(w: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&w[0].to_le_bytes());
    out[8..16].copy_from_slice(&w[1].to_le_bytes());
    out[16..24].copy_from_slice(&w[2].to_le_bytes());
    out[24..32].copy_from_slice(&w[3].to_le_bytes());
    out
}

#[inline]
fn limbs_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i = 4usize;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

#[inline]
fn limbs_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    let mut i = 0;
    while i < 4 {
        let ai = a[i] as u128;
        let bi = (b[i] as u128) + borrow;
        if ai >= bi {
            out[i] = (ai - bi) as u64;
            borrow = 0;
        } else {
            out[i] = ((1u128 << 64) + ai - bi) as u64;
            borrow = 1;
        }
        i += 1;
    }
    out
}

#[inline]
fn limbs_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 4 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    (out, carry as u64)
}

/// Checks whether `b` is a canonical little-endian scalar strictly `< ℓ`.
#[inline]
pub fn scalar_is_canonical(b: &[u8; 32]) -> bool {
    let w = limbs_from_le32(b);
    !limbs_gte(&w, &ORDER_L_LIMBS)
}

/// Converts a `u64` into a canonical 32-byte little-endian scalar in `ℤ_ℓ`.
#[inline]
pub const fn scalar_from_u64(v: u64) -> [u8; 32] {
    let b = v.to_le_bytes();
    let mut out = [0u8; 32];
    out[0] = b[0];
    out[1] = b[1];
    out[2] = b[2];
    out[3] = b[3];
    out[4] = b[4];
    out[5] = b[5];
    out[6] = b[6];
    out[7] = b[7];
    out
}

/// Negates a canonical scalar `a` modulo `ℓ` (`(ℓ - a) mod ℓ`).
#[inline]
pub fn scalar_neg(a: &[u8; 32]) -> [u8; 32] {
    if *a == [0u8; 32] {
        return [0u8; 32];
    }
    let wa = limbs_from_le32(a);
    limbs_to_le32(&limbs_sub(&ORDER_L_LIMBS, &wa))
}

/// Negates `Scalar::from(v)` modulo `ℓ`.
#[inline]
pub fn scalar_neg_u64(v: u64) -> [u8; 32] {
    scalar_neg(&scalar_from_u64(v))
}

/// Adds two canonical scalars modulo `ℓ`.
#[inline]
pub fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let wa = limbs_from_le32(a);
    let wb = limbs_from_le32(b);
    let (sum, carry) = limbs_add(&wa, &wb);
    if carry != 0 || limbs_gte(&sum, &ORDER_L_LIMBS) {
        limbs_to_le32(&limbs_sub(&sum, &ORDER_L_LIMBS))
    } else {
        limbs_to_le32(&sum)
    }
}

/// Subtracts two canonical scalars modulo `ℓ` (`(a - b) mod ℓ`).
#[inline]
pub fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    scalar_add(a, &scalar_neg(b))
}

const C_L_0: u64 = 0x5812_631a_5cf5_d3ed;
const C_L_1: u64 = 0x14de_f9de_a2f7_9cd6;
const BIAS_1_MOD_L: [u64; 7] = [
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0931_8d2e_7ae9_f680,
    0x6f7c_ef51_7bce_6b2c,
    0x0000_0000_0000_000a,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0008,
];
const BIAS_2_MOD_L: [u64; 7] = [
    0x498c_6973_d74f_b400,
    0x7be7_7a8b_de73_5960,
    0x0000_0000_0000_0053,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0040,
    0,
    0,
];
const BIAS_3_MOD_L: [u64; 7] = [
    0xb024_c634_b9eb_a7da,
    0x29bd_f3bd_45ef_39ac,
    0x0000_0000_0000_0000,
    0x2000_0000_0000_0000,
    0,
    0,
    0,
];

#[inline]
fn crandall_fold_mod_l<const N: usize>(x: &[u64; N], bias: &[u64; 7]) -> [u64; 7] {
    let lo = [
        x[0],
        x[1],
        x[2],
        x[3] & 0x0fff_ffff_ffff_ffff,
        0,
        0,
        0,
    ];
    let mut hi = [0u64; 5];
    let mut i = 0;
    while i < 5 {
        let low_part = if i + 3 < N { x[i + 3] >> 60 } else { 0 };
        let high_part = if i + 4 < N { x[i + 4] << 4 } else { 0 };
        hi[i] = low_part | high_part;
        i += 1;
    }

    // `prod = hi * C_L` (`5 x 2 -> 7` limbs)
    let mut prod = [0u64; 7];
    let mut carry = 0u128;
    i = 0;
    while i < 5 {
        let cur = (hi[i] as u128) * (C_L_0 as u128) + carry;
        prod[i] = cur as u64;
        carry = cur >> 64;
        i += 1;
    }
    prod[5] = carry as u64;

    carry = 0;
    i = 0;
    while i < 5 {
        let cur = (prod[i + 1] as u128) + (hi[i] as u128) * (C_L_1 as u128) + carry;
        prod[i + 1] = cur as u64;
        carry = cur >> 64;
        i += 1;
    }
    prod[6] = carry as u64;

    // `acc = lo + bias`, then `acc - prod` (guaranteed strictly non-negative by bias choice)
    let mut acc = [0u64; 7];
    carry = 0;
    i = 0;
    while i < 7 {
        let s = (lo[i] as u128) + (bias[i] as u128) + carry;
        acc[i] = s as u64;
        carry = s >> 64;
        i += 1;
    }

    let mut borrow = 0u128;
    i = 0;
    while i < 7 {
        let ai = acc[i] as u128;
        let bi = (prod[i] as u128) + borrow;
        if ai >= bi {
            acc[i] = (ai - bi) as u64;
            borrow = 0;
        } else {
            acc[i] = ((1u128 << 64) + ai - bi) as u64;
            borrow = 1;
        }
        i += 1;
    }
    acc
}

/// Fast 3-pass Crandall reduction modulo `ℓ = 2^{252} + c_ℓ` (`c_ℓ < 2^{125}`).
fn reduce_512_mod_l(wide8: [u64; 8]) -> [u8; 32] {
    let y = crandall_fold_mod_l(&wide8, &BIAS_1_MOD_L);
    let z = crandall_fold_mod_l(&y, &BIAS_2_MOD_L);
    let w = crandall_fold_mod_l(&z, &BIAS_3_MOD_L);
    let mut w4 = [w[0], w[1], w[2], w[3]];
    while limbs_gte(&w4, &ORDER_L_LIMBS) {
        w4 = limbs_sub(&w4, &ORDER_L_LIMBS);
    }
    limbs_to_le32(&w4)
}

/// Multiplies two canonical scalars modulo `ℓ`.
pub fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let wa = limbs_from_le32(a);
    let wb = limbs_from_le32(b);
    let mut prod = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0u128;
        let mut j = 0;
        while j < 4 {
            let cur = (prod[i + j] as u128) + (wa[i] as u128) * (wb[j] as u128) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
            j += 1;
        }
        prod[i + 4] = prod[i + 4].wrapping_add(carry as u64);
        i += 1;
    }
    reduce_512_mod_l(prod)
}

/// Reduces an arbitrary 32-byte hash (interpreted little-endian) into a non-zero scalar `∈ ℤ_ℓ^*`.
pub fn scalar_from_hash_nonzero(hash_32: &[u8; 32]) -> [u8; 32] {
    let w = limbs_from_le32(hash_32);
    let wide = [w[0], w[1], w[2], w[3], 0, 0, 0, 0];
    let red = reduce_512_mod_l(wide);
    if red == [0u8; 32] {
        scalar_from_u64(1)
    } else {
        red
    }
}

/// Reduces a 64-byte `Sha512` / wide hash (little-endian) modulo `ℓ`.
pub fn scalar_from_wide_le64(wide_64: &[u8; 64]) -> [u8; 32] {
    let mut w = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        let base = i * 8;
        w[i] = u64::from_le_bytes([
            wide_64[base],
            wide_64[base + 1],
            wide_64[base + 2],
            wide_64[base + 3],
            wide_64[base + 4],
            wide_64[base + 5],
            wide_64[base + 6],
            wide_64[base + 7],
        ]);
        i += 1;
    }
    reduce_512_mod_l(w)
}

// ---------------------------------------------------------------------------
// `#![no_std]` Fixed-Buffer Sparse R1CS Constraint System Builder
// ---------------------------------------------------------------------------

/// Zero-allocation builder for the compact sparse R1CS binary format consumed by `verify_r1cs`.
pub struct BpCsBuilder<const CAP: usize> {
    buf: [u8; CAP],
    len: usize,
    constraint_cnt: u16,
    cur_term_cnt_pos: usize,
    ok: bool,
}

impl<const CAP: usize> BpCsBuilder<CAP> {
    pub fn new(num_gates: u16, num_vars: u16) -> Self {
        let mut buf = [0u8; CAP];
        let g = num_gates.to_be_bytes();
        let v = num_vars.to_be_bytes();
        buf[0] = g[0];
        buf[1] = g[1];
        buf[2] = v[0];
        buf[3] = v[1];
        buf[4] = 0;
        buf[5] = 0;
        Self {
            buf,
            len: 6,
            constraint_cnt: 0,
            cur_term_cnt_pos: 0,
            ok: CAP >= 6,
        }
    }

    /// Starts a new linear constraint `∑ weight * wire == constant`.
    #[inline]
    pub fn begin_constraint(&mut self, constant_32: &[u8; 32]) -> bool {
        if !self.ok || self.len + 34 > CAP {
            self.ok = false;
            return false;
        }
        self.buf[self.len..self.len + 32].copy_from_slice(constant_32);
        self.cur_term_cnt_pos = self.len + 32;
        self.buf[self.cur_term_cnt_pos] = 0;
        self.buf[self.cur_term_cnt_pos + 1] = 0;
        self.len += 34;
        self.constraint_cnt = self.constraint_cnt.saturating_add(1);
        let c_be = self.constraint_cnt.to_be_bytes();
        self.buf[4] = c_be[0];
        self.buf[5] = c_be[1];
        true
    }

    /// Appends a sparse term `weight * wire[index]` to the current constraint.
    #[inline]
    pub fn push_term(&mut self, wire_kind: u8, index: u16, weight_32: &[u8; 32]) -> bool {
        if !self.ok || self.cur_term_cnt_pos == 0 || self.len + 35 > CAP {
            self.ok = false;
            return false;
        }
        let cur_terms = u16::from_be_bytes([
            self.buf[self.cur_term_cnt_pos],
            self.buf[self.cur_term_cnt_pos + 1],
        ]);
        let next_terms = cur_terms.saturating_add(1);
        let t_be = next_terms.to_be_bytes();
        self.buf[self.cur_term_cnt_pos] = t_be[0];
        self.buf[self.cur_term_cnt_pos + 1] = t_be[1];

        let i_be = index.to_be_bytes();
        self.buf[self.len] = wire_kind;
        self.buf[self.len + 1] = i_be[0];
        self.buf[self.len + 2] = i_be[1];
        self.buf[self.len + 3..self.len + 35].copy_from_slice(weight_32);
        self.len += 35;
        true
    }

    #[inline]
    pub fn as_slice(&self) -> Option<&[u8]> {
        if self.ok {
            Some(&self.buf[..self.len])
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Host-Target Prover & Verifier (`cargo test` / CLI / AI Operatives)
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub mod mock_bp {
    use std::sync::OnceLock;

    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE};
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
    use sha2::{Digest, Sha512};

    use super::{
        MAX_BP_GENERATORS, MAX_BP_R1CS_VARS, WIRE_A_L, WIRE_A_O, WIRE_A_R, WIRE_VAR,
    };
    use crate::vrf::mock_crypto::{decode_torsion_free_or_identity, hash_to_curve};

    pub const MAX_BP_R1CS_CONSTRAINTS: usize = 512;
    pub const MAX_BP_TERMS_PER_CONSTRAINT: usize = 256;

    pub struct BpGenerators {
        pub b_val: EdwardsPoint,
        pub h_blind: EdwardsPoint,
        pub u_ipa: EdwardsPoint,
        pub g_vec: [EdwardsPoint; MAX_BP_GENERATORS],
        pub h_vec: [EdwardsPoint; MAX_BP_GENERATORS],
    }

    static BP_GENS: OnceLock<BpGenerators> = OnceLock::new();

    pub fn generators() -> &'static BpGenerators {
        BP_GENS.get_or_init(|| {
            let h_blind = hash_to_curve(b"SLX_BP_H_BLIND_V1");
            let u_ipa = hash_to_curve(b"SLX_BP_U_IPA_V1");
            let g_vec = std::array::from_fn(|i| {
                let mut seed = [0u8; 20];
                seed[0..16].copy_from_slice(b"SLX_BP_G_VEC_V1:");
                seed[16..20].copy_from_slice(&(i as u32).to_be_bytes());
                hash_to_curve(&seed)
            });
            let h_vec = std::array::from_fn(|i| {
                let mut seed = [0u8; 20];
                seed[0..16].copy_from_slice(b"SLX_BP_H_VEC_V1:");
                seed[16..20].copy_from_slice(&(i as u32).to_be_bytes());
                hash_to_curve(&seed)
            });
            BpGenerators {
                b_val: ED25519_BASEPOINT_POINT,
                h_blind,
                u_ipa,
                g_vec,
                h_vec,
            }
        })
    }

    pub fn pedersen_blinding_generator_bytes() -> [u8; 32] {
        generators().h_blind.compress().to_bytes()
    }

    pub fn pedersen_commit(val: &Scalar, blind: &Scalar) -> [u8; 32] {
        let gens = generators();
        (val * ED25519_BASEPOINT_TABLE + blind * gens.h_blind)
            .compress()
            .to_bytes()
    }

    pub fn pedersen_commit_u64(val: u64, blind: &Scalar) -> [u8; 32] {
        pedersen_commit(&Scalar::from(val), blind)
    }

    #[derive(Clone)]
    pub struct BpTranscript {
        state: [u8; 32],
    }

    impl BpTranscript {
        pub fn new(domain: &[u8]) -> Self {
            let mut t = Self {
                state: *b"SLX_BP_TRANSCRIPT_INIT_V1_000000",
            };
            t.append_bytes(b"dom-sep", domain);
            t
        }

        pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
            let mut h = Sha512::new();
            h.update(b"SLX_BP_FS_ABSORB");
            h.update(self.state);
            h.update((label.len() as u32).to_be_bytes());
            h.update(label);
            h.update((data.len() as u32).to_be_bytes());
            h.update(data);
            let d = h.finalize();
            self.state.copy_from_slice(&d[0..32]);
        }

        pub fn append_u64(&mut self, label: &[u8], val: u64) {
            self.append_bytes(label, &val.to_be_bytes());
        }

        pub fn append_point(&mut self, label: &[u8], pt: &EdwardsPoint) {
            self.append_bytes(label, pt.compress().as_bytes());
        }

        pub fn append_scalar(&mut self, label: &[u8], sc: &Scalar) {
            self.append_bytes(label, sc.as_bytes());
        }

        pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
            let mut h = Sha512::new();
            h.update(b"SLX_BP_FS_SQUEEZE");
            h.update(self.state);
            h.update((label.len() as u32).to_be_bytes());
            h.update(label);
            let wide: [u8; 64] = h.finalize().into();

            let mut next_h = Sha512::new();
            next_h.update(b"SLX_BP_FS_NEXT");
            next_h.update(wide);
            let next_d = next_h.finalize();
            self.state.copy_from_slice(&next_d[0..32]);

            let sc = Scalar::from_bytes_mod_order_wide(&wide);
            if sc == Scalar::ZERO {
                Scalar::ONE
            } else {
                sc
            }
        }
    }

    fn derive_blinding_scalar(seed: &[u8; 32], domain: &[u8], idx: u32) -> Scalar {
        let mut h = Sha512::new();
        h.update(b"SLX_BP_BLIND_NONCE_V1");
        h.update(seed);
        h.update((domain.len() as u32).to_be_bytes());
        h.update(domain);
        h.update(idx.to_be_bytes());
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
        let mut acc = Scalar::ZERO;
        for (x, y) in a.iter().zip(b.iter()) {
            acc += x * y;
        }
        acc
    }

    fn powers_of(base: &Scalar, n: usize) -> Vec<Scalar> {
        let mut out = Vec::with_capacity(n);
        let mut cur = Scalar::ONE;
        for _ in 0..n {
            out.push(cur);
            cur *= base;
        }
        out
    }

    fn read_point(slice: &[u8], cursor: &mut usize) -> Option<EdwardsPoint> {
        if *cursor + 32 > slice.len() {
            return None;
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&slice[*cursor..*cursor + 32]);
        *cursor += 32;
        decode_torsion_free_or_identity(&b)
    }

    fn read_scalar(slice: &[u8], cursor: &mut usize) -> Option<Scalar> {
        if *cursor + 32 > slice.len() {
            return None;
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&slice[*cursor..*cursor + 32]);
        *cursor += 32;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
    }

    fn prove_ipa(
        transcript: &mut BpTranscript,
        mut g_vec: Vec<EdwardsPoint>,
        mut h_vec: Vec<EdwardsPoint>,
        q_pt: &EdwardsPoint,
        mut a_vec: Vec<Scalar>,
        mut b_vec: Vec<Scalar>,
        out_bytes: &mut Vec<u8>,
    ) {
        let mut n = a_vec.len();
        transcript.append_u64(b"ipa-n", n as u64);

        while n > 1 {
            let half = n / 2;
            let (a_l, a_r) = a_vec.split_at(half);
            let (b_l, b_r) = b_vec.split_at(half);
            let (g_l, g_r) = g_vec.split_at(half);
            let (h_l, h_r) = h_vec.split_at(half);

            let c_l = inner_product(a_l, b_r);
            let c_r = inner_product(a_r, b_l);

            let mut l_sc = Vec::with_capacity(2 * half + 1);
            let mut l_pt = Vec::with_capacity(2 * half + 1);
            l_sc.extend_from_slice(a_l);
            l_pt.extend_from_slice(g_r);
            l_sc.extend_from_slice(b_r);
            l_pt.extend_from_slice(h_l);
            l_sc.push(c_l);
            l_pt.push(*q_pt);
            let l_comm = EdwardsPoint::vartime_multiscalar_mul(l_sc.iter(), l_pt.iter());

            let mut r_sc = Vec::with_capacity(2 * half + 1);
            let mut r_pt = Vec::with_capacity(2 * half + 1);
            r_sc.extend_from_slice(a_r);
            r_pt.extend_from_slice(g_l);
            r_sc.extend_from_slice(b_l);
            r_pt.extend_from_slice(h_r);
            r_sc.push(c_r);
            r_pt.push(*q_pt);
            let r_comm = EdwardsPoint::vartime_multiscalar_mul(r_sc.iter(), r_pt.iter());

            out_bytes.extend_from_slice(l_comm.compress().as_bytes());
            out_bytes.extend_from_slice(r_comm.compress().as_bytes());

            transcript.append_point(b"L", &l_comm);
            transcript.append_point(b"R", &r_comm);
            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.invert();

            let mut next_a = Vec::with_capacity(half);
            let mut next_b = Vec::with_capacity(half);
            let mut next_g = Vec::with_capacity(half);
            let mut next_h = Vec::with_capacity(half);
            for i in 0..half {
                next_a.push(u * a_l[i] + u_inv * a_r[i]);
                next_b.push(u_inv * b_l[i] + u * b_r[i]);
                next_g.push(EdwardsPoint::vartime_multiscalar_mul(
                    [u_inv, u].iter(),
                    [g_l[i], g_r[i]].iter(),
                ));
                next_h.push(EdwardsPoint::vartime_multiscalar_mul(
                    [u, u_inv].iter(),
                    [h_l[i], h_r[i]].iter(),
                ));
            }
            a_vec = next_a;
            b_vec = next_b;
            g_vec = next_g;
            h_vec = next_h;
            n = half;
        }
        out_bytes.extend_from_slice(a_vec[0].as_bytes());
        out_bytes.extend_from_slice(b_vec[0].as_bytes());
    }

    fn ipa_verification_scalars(
        transcript: &mut BpTranscript,
        n: usize,
        l_pts: &[EdwardsPoint],
        r_pts: &[EdwardsPoint],
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let k = l_pts.len();
        transcript.append_u64(b"ipa-n", n as u64);

        let mut u_inv_challenges = Vec::with_capacity(k);
        let mut u_sq = Vec::with_capacity(k);
        let mut u_inv_sq = Vec::with_capacity(k);

        for j in 0..k {
            transcript.append_point(b"L", &l_pts[j]);
            transcript.append_point(b"R", &r_pts[j]);
            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.invert();
            u_inv_challenges.push(u_inv);
            u_sq.push(u * u);
            u_inv_sq.push(u_inv * u_inv);
        }

        let mut s = vec![Scalar::ZERO; n];
        let mut all_inv = Scalar::ONE;
        for u_inv in &u_inv_challenges {
            all_inv *= u_inv;
        }
        s[0] = all_inv;
        for i in 1..n {
            let lg_i = (usize::BITS - 1 - i.leading_zeros()) as usize;
            let bit_pos = 1usize << lg_i;
            let round_idx = k - 1 - lg_i;
            s[i] = s[i ^ bit_pos] * u_sq[round_idx];
        }
        let mut s_inv = s.clone();
        Scalar::batch_invert(&mut s_inv);
        (s, s_inv, u_sq, u_inv_sq)
    }

    pub fn is_valid_range_params(count: usize, bit_width: usize) -> bool {
        let valid_bits = matches!(bit_width, 8 | 16 | 24 | 32 | 64);
        let total = count.saturating_mul(bit_width);
        valid_bits && count > 0 && count.is_power_of_two() && total <= MAX_BP_GENERATORS
    }

    pub fn range_proof_byte_len(count: usize, bit_width: usize) -> usize {
        let n_tot = count * bit_width;
        let k = n_tot.trailing_zeros() as usize;
        (9 + 2 * k) * 32
    }

    fn range_delta(n: usize, m: usize, y: &Scalar, z: &Scalar) -> Scalar {
        let z2 = z * z;
        let sum_y: Scalar = powers_of(y, m * n).into_iter().sum();
        let sum_2: Scalar = powers_of(&Scalar::from(2u64), n).into_iter().sum();
        let mut sum_z_powers = Scalar::ZERO;
        let mut z_pow = z2 * z;
        for _ in 0..m {
            sum_z_powers += z_pow;
            z_pow *= z;
        }
        (*z - z2) * sum_y - sum_z_powers * sum_2
    }

    pub fn prove_range_u64_batch(
        values: &[u64],
        blindings: &[Scalar],
        bit_width: usize,
        ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<(Vec<[u8; 32]>, Vec<u8>)> {
        let m = values.len();
        if m != blindings.len() || !is_valid_range_params(m, bit_width) {
            return None;
        }
        for &v in values {
            if bit_width < 64 && (v >> bit_width) != 0 {
                return None;
            }
        }

        let gens = generators();
        let n_tot = m * bit_width;
        let commits: Vec<[u8; 32]> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, b)| pedersen_commit_u64(v, b))
            .collect();

        let mut a_l = Vec::with_capacity(n_tot);
        let mut a_r = Vec::with_capacity(n_tot);
        for &v in values {
            for bit in 0..bit_width {
                let sc_b = Scalar::from(((v >> bit) & 1) as u64);
                a_l.push(sc_b);
                a_r.push(sc_b - Scalar::ONE);
            }
        }

        let alpha = derive_blinding_scalar(entropy_32, b"range-alpha", 0);
        let rho = derive_blinding_scalar(entropy_32, b"range-rho", 1);
        let tau_1 = derive_blinding_scalar(entropy_32, b"range-tau1", 2);
        let tau_2 = derive_blinding_scalar(entropy_32, b"range-tau2", 3);
        let s_l: Vec<Scalar> = (0..n_tot)
            .map(|i| derive_blinding_scalar(entropy_32, b"range-sL", i as u32))
            .collect();
        let s_r: Vec<Scalar> = (0..n_tot)
            .map(|i| derive_blinding_scalar(entropy_32, b"range-sR", i as u32))
            .collect();

        let mut a_sc = vec![alpha];
        let mut a_pt = vec![gens.h_blind];
        a_sc.extend_from_slice(&a_l);
        a_pt.extend_from_slice(&gens.g_vec[..n_tot]);
        a_sc.extend_from_slice(&a_r);
        a_pt.extend_from_slice(&gens.h_vec[..n_tot]);
        let a_comm = EdwardsPoint::vartime_multiscalar_mul(a_sc.iter(), a_pt.iter());

        let mut s_sc = vec![rho];
        let mut s_pt = vec![gens.h_blind];
        s_sc.extend_from_slice(&s_l);
        s_pt.extend_from_slice(&gens.g_vec[..n_tot]);
        s_sc.extend_from_slice(&s_r);
        s_pt.extend_from_slice(&gens.h_vec[..n_tot]);
        let s_comm = EdwardsPoint::vartime_multiscalar_mul(s_sc.iter(), s_pt.iter());

        let mut tr = BpTranscript::new(b"SLX_BP_RANGE_U64_V1");
        tr.append_u64(b"m", m as u64);
        tr.append_u64(b"n", bit_width as u64);
        tr.append_bytes(b"ctx", ctx);
        for c in &commits {
            tr.append_bytes(b"V", c);
        }
        tr.append_point(b"A", &a_comm);
        tr.append_point(b"S", &s_comm);

        let y = tr.challenge_scalar(b"y");
        let z = tr.challenge_scalar(b"z");
        let y_pows = powers_of(&y, n_tot);
        let two_pows = powers_of(&Scalar::from(2u64), bit_width);
        let z2 = z * z;

        let mut z_two_vec = vec![Scalar::ZERO; n_tot];
        let mut z_j = z2;
        for j in 0..m {
            for bit in 0..bit_width {
                z_two_vec[j * bit_width + bit] = z_j * two_pows[bit];
            }
            z_j *= z;
        }

        let mut l0 = Vec::with_capacity(n_tot);
        let mut r0 = Vec::with_capacity(n_tot);
        let mut r1 = Vec::with_capacity(n_tot);
        for i in 0..n_tot {
            l0.push(a_l[i] - z);
            r0.push(y_pows[i] * (a_r[i] + z) + z_two_vec[i]);
            r1.push(y_pows[i] * s_r[i]);
        }

        let t1 = inner_product(&l0, &r1) + inner_product(&s_l, &r0);
        let t2 = inner_product(&s_l, &r1);
        let t1_comm = &t1 * ED25519_BASEPOINT_TABLE + tau_1 * gens.h_blind;
        let t2_comm = &t2 * ED25519_BASEPOINT_TABLE + tau_2 * gens.h_blind;

        tr.append_point(b"T1", &t1_comm);
        tr.append_point(b"T2", &t2_comm);
        let x = tr.challenge_scalar(b"x");

        let l_eval: Vec<Scalar> = (0..n_tot).map(|i| l0[i] + s_l[i] * x).collect();
        let r_eval: Vec<Scalar> = (0..n_tot).map(|i| r0[i] + r1[i] * x).collect();
        let t_hat = inner_product(&l_eval, &r_eval);

        let mut z_blind_sum = Scalar::ZERO;
        let mut z_pow = z2;
        for b_j in blindings {
            z_blind_sum += z_pow * b_j;
            z_pow *= z;
        }
        let tau_x = tau_2 * (x * x) + tau_1 * x + z_blind_sum;
        let mu = alpha + rho * x;

        tr.append_scalar(b"tau_x", &tau_x);
        tr.append_scalar(b"mu", &mu);
        tr.append_scalar(b"t_hat", &t_hat);
        let w = tr.challenge_scalar(b"w");
        let q_pt = w * gens.u_ipa;

        let y_inv_pows = powers_of(&y.invert(), n_tot);
        let h_prime: Vec<EdwardsPoint> = (0..n_tot)
            .map(|i| y_inv_pows[i] * gens.h_vec[i])
            .collect();

        let mut out = Vec::with_capacity(range_proof_byte_len(m, bit_width));
        out.extend_from_slice(a_comm.compress().as_bytes());
        out.extend_from_slice(s_comm.compress().as_bytes());
        out.extend_from_slice(t1_comm.compress().as_bytes());
        out.extend_from_slice(t2_comm.compress().as_bytes());
        out.extend_from_slice(tau_x.as_bytes());
        out.extend_from_slice(mu.as_bytes());
        out.extend_from_slice(t_hat.as_bytes());

        prove_ipa(
            &mut tr,
            gens.g_vec[..n_tot].to_vec(),
            h_prime,
            &q_pt,
            l_eval,
            r_eval,
            &mut out,
        );
        Some((commits, out))
    }

    pub fn verify_range_u64_batch(
        commits: &[[u8; 32]],
        bit_width: usize,
        ctx: &[u8],
        proof: &[u8],
    ) -> bool {
        let m = commits.len();
        if !is_valid_range_params(m, bit_width)
            || proof.len() != range_proof_byte_len(m, bit_width)
        {
            return false;
        }
        let mut v_pts = Vec::with_capacity(m);
        for c in commits {
            let Some(pt) = decode_torsion_free_or_identity(c) else {
                return false;
            };
            v_pts.push(pt);
        }

        let n_tot = m * bit_width;
        let k = n_tot.trailing_zeros() as usize;
        let mut cursor = 0usize;
        let (Some(a_comm), Some(s_comm), Some(t1_comm), Some(t2_comm)) = (
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
        ) else {
            return false;
        };
        let (Some(tau_x), Some(mu), Some(t_hat)) = (
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
        ) else {
            return false;
        };
        let mut l_pts = Vec::with_capacity(k);
        let mut r_pts = Vec::with_capacity(k);
        for _ in 0..k {
            let (Some(lp), Some(rp)) =
                (read_point(proof, &mut cursor), read_point(proof, &mut cursor))
            else {
                return false;
            };
            l_pts.push(lp);
            r_pts.push(rp);
        }
        let (Some(a_fin), Some(b_fin)) = (
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
        ) else {
            return false;
        };
        if cursor != proof.len() {
            return false;
        }

        let gens = generators();
        let mut tr = BpTranscript::new(b"SLX_BP_RANGE_U64_V1");
        tr.append_u64(b"m", m as u64);
        tr.append_u64(b"n", bit_width as u64);
        tr.append_bytes(b"ctx", ctx);
        for c in commits {
            tr.append_bytes(b"V", c);
        }
        tr.append_point(b"A", &a_comm);
        tr.append_point(b"S", &s_comm);

        let y = tr.challenge_scalar(b"y");
        let z = tr.challenge_scalar(b"z");
        tr.append_point(b"T1", &t1_comm);
        tr.append_point(b"T2", &t2_comm);
        let x = tr.challenge_scalar(b"x");

        tr.append_scalar(b"tau_x", &tau_x);
        tr.append_scalar(b"mu", &mu);
        tr.append_scalar(b"t_hat", &t_hat);
        let w = tr.challenge_scalar(b"w");

        let delta = range_delta(bit_width, m, &y, &z);
        let mut poly_sc = vec![delta - t_hat, -tau_x, x, x * x];
        let mut poly_pt = vec![gens.b_val, gens.h_blind, t1_comm, t2_comm];
        let mut z_pow = z * z;
        for vp in &v_pts {
            poly_sc.push(z_pow);
            poly_pt.push(*vp);
            z_pow *= z;
        }
        if EdwardsPoint::vartime_multiscalar_mul(poly_sc.iter(), poly_pt.iter())
            != EdwardsPoint::identity()
        {
            return false;
        }

        let (s_vec, s_inv_vec, u_sq, u_inv_sq) =
            ipa_verification_scalars(&mut tr, n_tot, &l_pts, &r_pts);
        let y_inv_pows = powers_of(&y.invert(), n_tot);
        let two_pows = powers_of(&Scalar::from(2u64), bit_width);
        let z2 = z * z;

        let mut msm_sc = Vec::with_capacity(2 * n_tot + 2 * k + 4);
        let mut msm_pt = Vec::with_capacity(2 * n_tot + 2 * k + 4);
        for i in 0..n_tot {
            msm_sc.push(a_fin * s_vec[i] + z);
            msm_pt.push(gens.g_vec[i]);
        }
        let mut z_j = z2;
        for j in 0..m {
            for bit in 0..bit_width {
                let i = j * bit_width + bit;
                msm_sc.push(y_inv_pows[i] * (b_fin * s_inv_vec[i] - z_j * two_pows[bit]) - z);
                msm_pt.push(gens.h_vec[i]);
            }
            z_j *= z;
        }
        msm_sc.extend_from_slice(&[(a_fin * b_fin - t_hat) * w, mu, -Scalar::ONE, -x]);
        msm_pt.extend_from_slice(&[gens.u_ipa, gens.h_blind, a_comm, s_comm]);
        for j in 0..k {
            msm_sc.push(-u_sq[j]);
            msm_pt.push(l_pts[j]);
            msm_sc.push(-u_inv_sq[j]);
            msm_pt.push(r_pts[j]);
        }

        EdwardsPoint::vartime_multiscalar_mul(msm_sc.iter(), msm_pt.iter())
            == EdwardsPoint::identity()
    }

    struct DecodedConstraint {
        constant: Scalar,
        terms: Vec<(u8, usize, Scalar)>,
    }

    fn decode_cs(bytes: &[u8]) -> Option<(usize, usize, Vec<DecodedConstraint>)> {
        if bytes.len() < 6 {
            return None;
        }
        let num_gates = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let num_vars = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let num_constraints = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if num_gates == 0
            || !num_gates.is_power_of_two()
            || num_gates > MAX_BP_GENERATORS
            || num_vars > MAX_BP_R1CS_VARS
            || num_constraints > MAX_BP_R1CS_CONSTRAINTS
        {
            return None;
        }
        let mut cursor = 6usize;
        let mut out = Vec::with_capacity(num_constraints);
        for _ in 0..num_constraints {
            let constant = read_scalar(bytes, &mut cursor)?;
            if cursor + 2 > bytes.len() {
                return None;
            }
            let t_cnt = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if t_cnt > MAX_BP_TERMS_PER_CONSTRAINT || cursor + t_cnt * 35 > bytes.len() {
                return None;
            }
            let mut terms = Vec::with_capacity(t_cnt);
            for _ in 0..t_cnt {
                let wk = bytes[cursor];
                let idx = u16::from_be_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
                cursor += 3;
                let weight = read_scalar(bytes, &mut cursor)?;
                let ok = match wk {
                    WIRE_A_L | WIRE_A_R | WIRE_A_O => idx < num_gates,
                    WIRE_VAR => idx < num_vars,
                    _ => false,
                };
                if !ok {
                    return None;
                }
                terms.push((wk, idx, weight));
            }
            out.push(DecodedConstraint { constant, terms });
        }
        if cursor != bytes.len() {
            return None;
        }
        Some((num_gates, num_vars, out))
    }

    fn flatten_cs(
        num_gates: usize,
        num_vars: usize,
        constraints: &[DecodedConstraint],
        z: &Scalar,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {
        let mut w_l = vec![Scalar::ZERO; num_gates];
        let mut w_r = vec![Scalar::ZERO; num_gates];
        let mut w_o = vec![Scalar::ZERO; num_gates];
        let mut w_v = vec![Scalar::ZERO; num_vars];
        let mut c_acc = Scalar::ZERO;

        let mut z_pow = *z;
        for c in constraints {
            c_acc += z_pow * c.constant;
            for &(wk, idx, weight) in &c.terms {
                let weighted = z_pow * weight;
                match wk {
                    WIRE_A_L => w_l[idx] += weighted,
                    WIRE_A_R => w_r[idx] += weighted,
                    WIRE_A_O => w_o[idx] += weighted,
                    WIRE_VAR => w_v[idx] += weighted,
                    _ => {}
                }
            }
            z_pow *= z;
        }
        (w_l, w_r, w_o, w_v, c_acc)
    }

    pub fn r1cs_proof_byte_len(num_gates: usize) -> usize {
        (13 + 2 * (num_gates.trailing_zeros() as usize)) * 32
    }

    pub fn prove_r1cs(
        cs_bytes: &[u8],
        var_values: &[Scalar],
        var_blindings: &[Scalar],
        a_l: &[Scalar],
        a_r: &[Scalar],
        a_o: &[Scalar],
        ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<(Vec<[u8; 32]>, Vec<u8>)> {
        let (n, k_vars, constraints) = decode_cs(cs_bytes)?;
        if var_values.len() != k_vars
            || var_blindings.len() != k_vars
            || a_l.len() != n
            || a_r.len() != n
            || a_o.len() != n
        {
            return None;
        }
        for i in 0..n {
            if a_l[i] * a_r[i] != a_o[i] {
                return None;
            }
        }
        for c in &constraints {
            let mut lhs = Scalar::ZERO;
            for &(wk, idx, weight) in &c.terms {
                let v = match wk {
                    WIRE_A_L => a_l[idx],
                    WIRE_A_R => a_r[idx],
                    WIRE_A_O => a_o[idx],
                    WIRE_VAR => var_values[idx],
                    _ => return None,
                };
                lhs += weight * v;
            }
            if lhs != c.constant {
                return None;
            }
        }

        let gens = generators();
        let commits: Vec<[u8; 32]> = var_values
            .iter()
            .zip(var_blindings.iter())
            .map(|(v, b)| pedersen_commit(v, b))
            .collect();

        let alpha_i = derive_blinding_scalar(entropy_32, b"r1cs-alphaI", 0);
        let alpha_o = derive_blinding_scalar(entropy_32, b"r1cs-alphaO", 1);
        let rho = derive_blinding_scalar(entropy_32, b"r1cs-rho", 2);
        let tau_1 = derive_blinding_scalar(entropy_32, b"r1cs-tau1", 3);
        let tau_3 = derive_blinding_scalar(entropy_32, b"r1cs-tau3", 4);
        let tau_4 = derive_blinding_scalar(entropy_32, b"r1cs-tau4", 5);
        let tau_5 = derive_blinding_scalar(entropy_32, b"r1cs-tau5", 6);
        let tau_6 = derive_blinding_scalar(entropy_32, b"r1cs-tau6", 7);
        let s_l: Vec<Scalar> = (0..n)
            .map(|i| derive_blinding_scalar(entropy_32, b"r1cs-sL", i as u32))
            .collect();
        let s_r: Vec<Scalar> = (0..n)
            .map(|i| derive_blinding_scalar(entropy_32, b"r1cs-sR", i as u32))
            .collect();

        let mut ai_sc = vec![alpha_i];
        let mut ai_pt = vec![gens.h_blind];
        ai_sc.extend_from_slice(a_l);
        ai_pt.extend_from_slice(&gens.g_vec[..n]);
        ai_sc.extend_from_slice(a_r);
        ai_pt.extend_from_slice(&gens.h_vec[..n]);
        let a_i_comm = EdwardsPoint::vartime_multiscalar_mul(ai_sc.iter(), ai_pt.iter());

        let mut ao_sc = vec![alpha_o];
        let mut ao_pt = vec![gens.h_blind];
        ao_sc.extend_from_slice(a_o);
        ao_pt.extend_from_slice(&gens.g_vec[..n]);
        let a_o_comm = EdwardsPoint::vartime_multiscalar_mul(ao_sc.iter(), ao_pt.iter());

        let mut s_sc = vec![rho];
        let mut s_pt = vec![gens.h_blind];
        s_sc.extend_from_slice(&s_l);
        s_pt.extend_from_slice(&gens.g_vec[..n]);
        s_sc.extend_from_slice(&s_r);
        s_pt.extend_from_slice(&gens.h_vec[..n]);
        let s_comm = EdwardsPoint::vartime_multiscalar_mul(s_sc.iter(), s_pt.iter());

        let mut tr = BpTranscript::new(b"SLX_BP_R1CS_V1");
        tr.append_bytes(b"cs", cs_bytes);
        tr.append_bytes(b"ctx", ctx);
        for c in &commits {
            tr.append_bytes(b"V", c);
        }
        tr.append_point(b"A_I", &a_i_comm);
        tr.append_point(b"A_O", &a_o_comm);
        tr.append_point(b"S", &s_comm);

        let y = tr.challenge_scalar(b"y");
        let z = tr.challenge_scalar(b"z");
        let y_pows = powers_of(&y, n);
        let y_inv_pows = powers_of(&y.invert(), n);
        let (w_l, w_r, w_o, w_v, _) = flatten_cs(n, k_vars, &constraints, &z);

        let mut l1 = Vec::with_capacity(n);
        let mut r0 = Vec::with_capacity(n);
        let mut r1 = Vec::with_capacity(n);
        let mut r3 = Vec::with_capacity(n);
        for i in 0..n {
            l1.push(a_l[i] + y_inv_pows[i] * w_r[i]);
            r0.push(w_o[i] - y_pows[i]);
            r1.push(y_pows[i] * a_r[i] + w_l[i]);
            r3.push(y_pows[i] * s_r[i]);
        }

        let t1 = inner_product(&l1, &r0);
        let t3 = inner_product(a_o, &r1) + inner_product(&s_l, &r0);
        let t4 = inner_product(&l1, &r3) + inner_product(&s_l, &r1);
        let t5 = inner_product(a_o, &r3);
        let t6 = inner_product(&s_l, &r3);

        let commit_t = |val: &Scalar, blind: &Scalar| -> EdwardsPoint {
            val * ED25519_BASEPOINT_TABLE + blind * gens.h_blind
        };
        let t1_comm = commit_t(&t1, &tau_1);
        let t3_comm = commit_t(&t3, &tau_3);
        let t4_comm = commit_t(&t4, &tau_4);
        let t5_comm = commit_t(&t5, &tau_5);
        let t6_comm = commit_t(&t6, &tau_6);

        tr.append_point(b"T1", &t1_comm);
        tr.append_point(b"T3", &t3_comm);
        tr.append_point(b"T4", &t4_comm);
        tr.append_point(b"T5", &t5_comm);
        tr.append_point(b"T6", &t6_comm);
        let x = tr.challenge_scalar(b"x");

        let x2 = x * x;
        let x3 = x2 * x;
        let x4 = x2 * x2;
        let x5 = x4 * x;
        let x6 = x3 * x3;

        let l_eval: Vec<Scalar> = (0..n)
            .map(|i| l1[i] * x + a_o[i] * x2 + s_l[i] * x3)
            .collect();
        let r_eval: Vec<Scalar> = (0..n)
            .map(|i| r0[i] + r1[i] * x + r3[i] * x3)
            .collect();
        let t_hat = inner_product(&l_eval, &r_eval);

        let w_v_gamma = inner_product(&w_v, var_blindings);
        let tau_x = tau_1 * x - w_v_gamma * x2 + tau_3 * x3 + tau_4 * x4 + tau_5 * x5 + tau_6 * x6;
        let mu = alpha_i * x + alpha_o * x2 + rho * x3;

        tr.append_scalar(b"tau_x", &tau_x);
        tr.append_scalar(b"mu", &mu);
        tr.append_scalar(b"t_hat", &t_hat);
        let w = tr.challenge_scalar(b"w");
        let q_pt = w * gens.u_ipa;

        let h_prime: Vec<EdwardsPoint> =
            (0..n).map(|i| y_inv_pows[i] * gens.h_vec[i]).collect();

        let mut out = Vec::with_capacity(r1cs_proof_byte_len(n));
        out.extend_from_slice(a_i_comm.compress().as_bytes());
        out.extend_from_slice(a_o_comm.compress().as_bytes());
        out.extend_from_slice(s_comm.compress().as_bytes());
        out.extend_from_slice(t1_comm.compress().as_bytes());
        out.extend_from_slice(t3_comm.compress().as_bytes());
        out.extend_from_slice(t4_comm.compress().as_bytes());
        out.extend_from_slice(t5_comm.compress().as_bytes());
        out.extend_from_slice(t6_comm.compress().as_bytes());
        out.extend_from_slice(tau_x.as_bytes());
        out.extend_from_slice(mu.as_bytes());
        out.extend_from_slice(t_hat.as_bytes());

        prove_ipa(
            &mut tr,
            gens.g_vec[..n].to_vec(),
            h_prime,
            &q_pt,
            l_eval,
            r_eval,
            &mut out,
        );
        Some((commits, out))
    }

    pub fn verify_r1cs(
        cs_bytes: &[u8],
        commits: &[[u8; 32]],
        ctx: &[u8],
        proof: &[u8],
    ) -> bool {
        let Some((n, k_vars, constraints)) = decode_cs(cs_bytes) else {
            return false;
        };
        if commits.len() != k_vars || proof.len() != r1cs_proof_byte_len(n) {
            return false;
        }
        let mut v_pts = Vec::with_capacity(k_vars);
        for c in commits {
            let Some(pt) = decode_torsion_free_or_identity(c) else {
                return false;
            };
            v_pts.push(pt);
        }

        let k_ipa = n.trailing_zeros() as usize;
        let mut cursor = 0usize;
        let (
            Some(a_i_comm),
            Some(a_o_comm),
            Some(s_comm),
            Some(t1_comm),
            Some(t3_comm),
            Some(t4_comm),
            Some(t5_comm),
            Some(t6_comm),
        ) = (
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
            read_point(proof, &mut cursor),
        ) else {
            return false;
        };
        let (Some(tau_x), Some(mu), Some(t_hat)) = (
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
        ) else {
            return false;
        };
        let mut l_pts = Vec::with_capacity(k_ipa);
        let mut r_pts = Vec::with_capacity(k_ipa);
        for _ in 0..k_ipa {
            let (Some(lp), Some(rp)) =
                (read_point(proof, &mut cursor), read_point(proof, &mut cursor))
            else {
                return false;
            };
            l_pts.push(lp);
            r_pts.push(rp);
        }
        let (Some(a_fin), Some(b_fin)) = (
            read_scalar(proof, &mut cursor),
            read_scalar(proof, &mut cursor),
        ) else {
            return false;
        };
        if cursor != proof.len() {
            return false;
        }

        let gens = generators();
        let mut tr = BpTranscript::new(b"SLX_BP_R1CS_V1");
        tr.append_bytes(b"cs", cs_bytes);
        tr.append_bytes(b"ctx", ctx);
        for c in commits {
            tr.append_bytes(b"V", c);
        }
        tr.append_point(b"A_I", &a_i_comm);
        tr.append_point(b"A_O", &a_o_comm);
        tr.append_point(b"S", &s_comm);

        let y = tr.challenge_scalar(b"y");
        let z = tr.challenge_scalar(b"z");
        tr.append_point(b"T1", &t1_comm);
        tr.append_point(b"T3", &t3_comm);
        tr.append_point(b"T4", &t4_comm);
        tr.append_point(b"T5", &t5_comm);
        tr.append_point(b"T6", &t6_comm);
        let x = tr.challenge_scalar(b"x");

        tr.append_scalar(b"tau_x", &tau_x);
        tr.append_scalar(b"mu", &mu);
        tr.append_scalar(b"t_hat", &t_hat);
        let w = tr.challenge_scalar(b"w");

        let y_inv_pows = powers_of(&y.invert(), n);
        let (w_l, w_r, w_o, w_v, c_acc) = flatten_cs(n, k_vars, &constraints, &z);

        let mut delta_r1cs = Scalar::ZERO;
        for i in 0..n {
            delta_r1cs += y_inv_pows[i] * w_r[i] * w_l[i];
        }

        let x2 = x * x;
        let x3 = x2 * x;
        let x4 = x2 * x2;
        let x5 = x4 * x;
        let x6 = x3 * x3;

        let mut poly_sc = vec![x2 * (c_acc + delta_r1cs) - t_hat, -tau_x, x, x3, x4, x5, x6];
        let mut poly_pt = vec![
            gens.b_val, gens.h_blind, t1_comm, t3_comm, t4_comm, t5_comm, t6_comm,
        ];
        for j in 0..k_vars {
            poly_sc.push(-x2 * w_v[j]);
            poly_pt.push(v_pts[j]);
        }
        if EdwardsPoint::vartime_multiscalar_mul(poly_sc.iter(), poly_pt.iter())
            != EdwardsPoint::identity()
        {
            return false;
        }

        let (s_vec, s_inv_vec, u_sq, u_inv_sq) =
            ipa_verification_scalars(&mut tr, n, &l_pts, &r_pts);
        let mut msm_sc = Vec::with_capacity(2 * n + 2 * k_ipa + 5);
        let mut msm_pt = Vec::with_capacity(2 * n + 2 * k_ipa + 5);
        for i in 0..n {
            msm_sc.push(a_fin * s_vec[i] - x * y_inv_pows[i] * w_r[i]);
            msm_pt.push(gens.g_vec[i]);
        }
        for i in 0..n {
            msm_sc.push(
                y_inv_pows[i] * (b_fin * s_inv_vec[i] - x * w_l[i] - w_o[i]) + Scalar::ONE,
            );
            msm_pt.push(gens.h_vec[i]);
        }
        msm_sc.extend_from_slice(&[(a_fin * b_fin - t_hat) * w, mu, -x, -x2, -x3]);
        msm_pt.extend_from_slice(&[gens.u_ipa, gens.h_blind, a_i_comm, a_o_comm, s_comm]);
        for j in 0..k_ipa {
            msm_sc.push(-u_sq[j]);
            msm_pt.push(l_pts[j]);
            msm_sc.push(-u_inv_sq[j]);
            msm_pt.push(r_pts[j]);
        }

        EdwardsPoint::vartime_multiscalar_mul(msm_sc.iter(), msm_pt.iter())
            == EdwardsPoint::identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    #[test]
    fn h_blind_constant_and_no_std_scalar_math_match_dalek() {
        let actual_h = mock_bp::pedersen_blinding_generator_bytes();
        if actual_h != BP_H_BLIND_BYTES {
            panic!("Update BP_H_BLIND_BYTES to: {:02x?}", actual_h);
        }

        for i in 0..200u64 {
            let mut h1 = Sha512::new();
            h1.update(b"sc-a");
            h1.update(i.to_le_bytes());
            let w1: [u8; 64] = h1.finalize().into();

            let mut h2 = Sha512::new();
            h2.update(b"sc-b");
            h2.update(i.to_le_bytes());
            let w2: [u8; 64] = h2.finalize().into();

            let da = Scalar::from_bytes_mod_order_wide(&w1);
            let db = Scalar::from_bytes_mod_order_wide(&w2);
            let a_32 = scalar_from_wide_le64(&w1);
            let b_32 = scalar_from_wide_le64(&w2);
            assert_eq!(a_32, *da.as_bytes());
            assert_eq!(b_32, *db.as_bytes());
            assert!(scalar_is_canonical(&a_32));
            assert_eq!(scalar_add(&a_32, &b_32), *(da + db).as_bytes());
            assert_eq!(scalar_sub(&a_32, &b_32), *(da - db).as_bytes());
            assert_eq!(scalar_mul(&a_32, &b_32), *(da * db).as_bytes());
            assert_eq!(scalar_neg(&a_32), *(-da).as_bytes());
        }
    }

    #[test]
    fn bp_cs_builder_and_r1cs_roundtrip() {
        let mut b = BpCsBuilder::<1024>::new(2, 2);
        // Gate 0: v0 * v1 = a_O[0] == 42
        let zero = [0u8; 32];
        let one = scalar_from_u64(1);
        let minus_one = scalar_neg_u64(1);
        b.begin_constraint(&zero);
        b.push_term(WIRE_A_L, 0, &one);
        b.push_term(WIRE_VAR, 0, &minus_one);
        b.begin_constraint(&zero);
        b.push_term(WIRE_A_R, 0, &one);
        b.push_term(WIRE_VAR, 1, &minus_one);
        b.begin_constraint(&scalar_from_u64(42));
        b.push_term(WIRE_A_O, 0, &one);

        let cs = b.as_slice().unwrap();
        let (commits, proof) = mock_bp::prove_r1cs(
            cs,
            &[Scalar::from(6u64), Scalar::from(7u64)],
            &[Scalar::from(19u64), Scalar::from(23u64)],
            &[Scalar::from(6u64), Scalar::ZERO],
            &[Scalar::from(7u64), Scalar::ZERO],
            &[Scalar::from(42u64), Scalar::ZERO],
            b"sdk-test",
            &[0x11; 32],
        )
        .unwrap();
        assert!(verify_r1cs(cs, &commits, b"sdk-test", &proof));
    }
}
