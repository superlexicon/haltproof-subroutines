//! Validator-Quorum Threshold ECVRF, DKG, Chaum-Pedersen DLEQ & Vector ElGamal guest bindings (`hps_sdk::vrf`).
//!
//! - On `wasm32`: zero-dependency `#![no_std]` wrappers over `WasmtimeAdapter`'s deterministic
//!   `env::host_active_validators`, `env::host_vrf_*`, and `env::host_ec_*` host precompiles.
//! - On host targets (`cargo test`): full native `Edwards25519` prime-order-`ℓ` simulation matching
//!   `lexicon/src/vm/vrf.rs` byte-for-byte, plus `mock_crypto` helpers for multi-validator DKG & VRF tests.

pub const MAX_VRF_VALIDATORS: usize = 64;

/// Canonical compressed `Edwards25519` basepoint `B` (RFC 8032 §5.1).
pub const ED25519_BASEPOINT_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Canonical compressed `Edwards25519` identity point `𝒪 = (0, 1)`.
pub const IDENTITY_POINT_BYTES: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Additive identity ElGamal ciphertext `Enc(0; r=0) = (𝒪, 𝒪)` (`64` bytes).
pub const IDENTITY_CIPHERTEXT_64: [u8; 64] = {
    let mut b = [0u8; 64];
    b[0] = 1;
    b[32] = 1;
    b
};

/// Canonical little-endian scalar `1 ∈ ℤ_ℓ`.
pub const SCALAR_ONE_BYTES: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Canonical little-endian scalar `-1 mod ℓ` (`ℓ - 1`).
pub const SCALAR_MINUS_ONE_BYTES: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Active `Full` validator record returned by [`active_validators`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveValidator {
    pub address: [u8; 20],
    pub pubkey: [u8; 32],
}

impl ActiveValidator {
    pub const ZERO: Self = Self {
        address: [0u8; 20],
        pubkey: [0u8; 32],
    };
}

/// Snapshot of the current active `Full` validator set from consensus `GlobalAccountState`,
/// sorted canonically by 32-byte Ed25519 public key ascending.
#[derive(Clone, Copy, Debug)]
pub struct ActiveValidatorSet {
    pub count: usize,
    pub threshold: usize,
    pub set_hash: [u8; 32],
    pub validators: [ActiveValidator; MAX_VRF_VALIDATORS],
}

impl ActiveValidatorSet {
    pub fn slice(&self) -> &[ActiveValidator] {
        &self.validators[..self.count]
    }

    pub fn pubkeys_into<'a>(&self, out: &'a mut [[u8; 32]; MAX_VRF_VALIDATORS]) -> &'a [[u8; 32]] {
        let mut i = 0;
        while i < self.count {
            out[i] = self.validators[i].pubkey;
            i += 1;
        }
        &out[..self.count]
    }
}

/// Minimum BFT-safe validator threshold `t` (`n` for `n <= 4`, `(2 * n) / 3 + 1` for `n >= 5`).
#[inline]
pub const fn min_safe_validator_threshold(n: usize) -> usize {
    if n == 0 {
        0
    } else if n <= 4 {
        n
    } else {
        ((2 * n) / 3) + 1
    }
}

/// Expected byte length of a serialized validator DKG deal for `(threshold, validator_count)`.
#[inline]
pub const fn dkg_deal_byte_len(threshold: usize, validator_count: usize) -> usize {
    32 + (threshold + validator_count) * 32 + 128
}

#[cfg(target_arch = "wasm32")]
mod sys {
    #[link(wasm_import_module = "env")]
    extern "C" {
        pub fn host_active_validators(out_ptr: i32, out_cap: i32) -> i32;
        pub fn host_vrf_verify_deal(
            set_hash_ptr: i32,
            dealer_idx: i32,
            threshold: i32,
            pks_ptr: i32,
            pks_count: i32,
            deal_ptr: i32,
            deal_len: i32,
        ) -> i32;
        pub fn host_vrf_verify_dispute(
            set_hash_ptr: i32,
            dealer_idx: i32,
            accuser_idx: i32,
            threshold: i32,
            pks_ptr: i32,
            pks_count: i32,
            deal_ptr: i32,
            deal_len: i32,
            shared_pt_ptr: i32,
            proof_ptr: i32,
        ) -> i32;
        pub fn host_vrf_derive_epoch_keys(
            threshold: i32,
            val_count: i32,
            deals_ptr: i32,
            deals_count: i32,
            deal_stride: i32,
            out_ptr: i32,
        ) -> i32;
        pub fn host_vrf_verify_share(
            share_pk_ptr: i32,
            alpha_ptr: i32,
            alpha_len: i32,
            gamma_ptr: i32,
            proof_ptr: i32,
        ) -> i32;
        pub fn host_vrf_lagrange_combine(
            epoch_pk_ptr: i32,
            alpha_ptr: i32,
            alpha_len: i32,
            shares_ptr: i32,
            shares_count: i32,
            out_64_ptr: i32,
        ) -> i32;
        pub fn host_ec_elgamal_lincomb(
            s1_ptr: i32,
            p1_ptr: i32,
            s2_ptr: i32,
            p2_ptr: i32,
            out_32_ptr: i32,
        ) -> i32;
        pub fn host_ec_dleq_verify(
            g1_ptr: i32,
            y1_ptr: i32,
            g2_ptr: i32,
            y2_ptr: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_64_ptr: i32,
        ) -> i32;
        pub fn host_he_add_ciphertexts(
            ca_64_ptr: i32,
            cb_64_ptr: i32,
            out_64_ptr: i32,
        ) -> i32;
        pub fn host_he_scale_ciphertext(
            ct_64_ptr: i32,
            weight: i64,
            out_64_ptr: i32,
        ) -> i32;
        pub fn host_he_verify_zero_or_one(
            pk_32_ptr: i32,
            ct_64_ptr: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_128_ptr: i32,
        ) -> i32;
        pub fn host_he_verify_pok(
            pk_32_ptr: i32,
            ct_64_ptr: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_96_ptr: i32,
        ) -> i32;
        pub fn host_he_verify_decryption_share(
            share_pk_ptr: i32,
            c1_ptr: i32,
            d_i_ptr: i32,
            ctx_ptr: i32,
            ctx_len: i32,
            proof_64_ptr: i32,
        ) -> i32;
        pub fn host_he_lagrange_decrypt(
            c1_ptr: i32,
            c2_ptr: i32,
            shares_ptr: i32,
            shares_count: i32,
            max_val: i64,
            out_72_ptr: i32,
        ) -> i32;
    }
}

/// Query the live consensus `Full` validator set, automatic BFT-safe threshold, and `set_hash`.
pub fn active_validators() -> Option<ActiveValidatorSet> {
    const BUF_CAP: usize = 40 + MAX_VRF_VALIDATORS * 52;
    let mut raw = [0u8; BUF_CAP];

    #[cfg(target_arch = "wasm32")]
    let rc = unsafe { sys::host_active_validators(raw.as_mut_ptr() as i32, BUF_CAP as i32) };

    #[cfg(not(target_arch = "wasm32"))]
    let rc = mock_crypto::fill_active_validators_blob(&mut raw);

    if rc < 0 {
        return None;
    }
    let count = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let threshold = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    if count > MAX_VRF_VALIDATORS || count != (rc as usize) {
        return None;
    }
    let mut set_hash = [0u8; 32];
    set_hash.copy_from_slice(&raw[8..40]);

    let mut validators = [ActiveValidator::ZERO; MAX_VRF_VALIDATORS];
    let mut i = 0;
    while i < count {
        let base = 40 + i * 52;
        validators[i].address.copy_from_slice(&raw[base..base + 20]);
        validators[i].pubkey.copy_from_slice(&raw[base + 20..base + 52]);
        i += 1;
    }
    Some(ActiveValidatorSet {
        count,
        threshold,
        set_hash,
        validators,
    })
}

/// Verify a validator DKG deal against `(set_hash, dealer_idx, threshold, validator_pubkeys)`.
pub fn verify_dkg_deal(
    set_hash: &[u8; 32],
    dealer_idx: usize,
    threshold: usize,
    validator_pubkeys: &[[u8; 32]],
    deal: &[u8],
) -> bool {
    if validator_pubkeys.is_empty() || validator_pubkeys.len() > MAX_VRF_VALIDATORS {
        return false;
    }
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_vrf_verify_deal(
            set_hash.as_ptr() as i32,
            dealer_idx as i32,
            threshold as i32,
            validator_pubkeys.as_ptr() as i32,
            validator_pubkeys.len() as i32,
            deal.as_ptr() as i32,
            deal.len() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_validator_dkg_deal(
            set_hash,
            dealer_idx,
            threshold,
            validator_pubkeys,
            deal,
        )
    }
}

/// Verify an objective Chaum-Pedersen DLEQ fraud dispute against `dealer_idx`'s DKG deal.
pub fn verify_dkg_dispute(
    set_hash: &[u8; 32],
    dealer_idx: usize,
    accuser_idx: usize,
    threshold: usize,
    validator_pubkeys: &[[u8; 32]],
    deal: &[u8],
    shared_pt: &[u8; 32],
    proof_64: &[u8; 64],
) -> bool {
    if validator_pubkeys.is_empty() || validator_pubkeys.len() > MAX_VRF_VALIDATORS {
        return false;
    }
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_vrf_verify_dispute(
            set_hash.as_ptr() as i32,
            dealer_idx as i32,
            accuser_idx as i32,
            threshold as i32,
            validator_pubkeys.as_ptr() as i32,
            validator_pubkeys.len() as i32,
            deal.as_ptr() as i32,
            deal.len() as i32,
            shared_pt.as_ptr() as i32,
            proof_64.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_dkg_share_dispute(
            set_hash,
            dealer_idx,
            accuser_idx,
            threshold,
            validator_pubkeys,
            deal,
            shared_pt,
            proof_64,
        )
    }
}

/// Derive `(epoch_pk_32, per_validator_share_pks)` from `deals_count` packed deals of stride `deal_stride`.
/// Writes `share_pks[0..val_count]` into `share_pks_out` and returns `Some(epoch_pk_32)` on success.
pub fn derive_epoch_keys(
    threshold: usize,
    val_count: usize,
    packed_deals: &[u8],
    deals_count: usize,
    deal_stride: usize,
    share_pks_out: &mut [[u8; 32]; MAX_VRF_VALIDATORS],
) -> Option<[u8; 32]> {
    if threshold == 0
        || val_count == 0
        || val_count > MAX_VRF_VALIDATORS
        || deals_count == 0
        || deals_count > MAX_VRF_VALIDATORS
        || packed_deals.len() < deals_count.saturating_mul(deal_stride)
    {
        return None;
    }
    let mut out_buf = [[0u8; 32]; MAX_VRF_VALIDATORS + 1];

    #[cfg(target_arch = "wasm32")]
    let ok = unsafe {
        sys::host_vrf_derive_epoch_keys(
            threshold as i32,
            val_count as i32,
            packed_deals.as_ptr() as i32,
            deals_count as i32,
            deal_stride as i32,
            out_buf.as_mut_ptr() as i32,
        ) == 1
    };

    #[cfg(not(target_arch = "wasm32"))]
    let ok = mock_crypto::derive_epoch_keys_packed(
        threshold,
        val_count,
        packed_deals,
        deals_count,
        deal_stride,
        &mut out_buf,
    );

    if !ok {
        return None;
    }
    let mut i = 0;
    while i < val_count {
        share_pks_out[i] = out_buf[1 + i];
        i += 1;
    }
    Some(out_buf[0])
}

/// Verify validator `j`'s partial ECVRF share `(gamma_32, proof_64)` against `share_pk_32` and `alpha`.
pub fn verify_vrf_share(
    share_pk: &[u8; 32],
    alpha: &[u8],
    gamma: &[u8; 32],
    proof_64: &[u8; 64],
) -> bool {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_vrf_verify_share(
            share_pk.as_ptr() as i32,
            alpha.as_ptr() as i32,
            alpha.len() as i32,
            gamma.as_ptr() as i32,
            proof_64.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_validator_vrf_share(share_pk, alpha, gamma, proof_64)
    }
}

/// Lagrange-combine `shares_count` partial VRF points (`packed_36b_shares`: `[idx_u32_be || gamma_32]`)
/// into `(combined_gamma_32, unbiased_random_32)`.
pub fn lagrange_combine(
    epoch_pk: &[u8; 32],
    alpha: &[u8],
    packed_36b_shares: &[u8],
    shares_count: usize,
) -> Option<([u8; 32], [u8; 32])> {
    if shares_count == 0
        || shares_count > MAX_VRF_VALIDATORS
        || packed_36b_shares.len() < shares_count * 36
    {
        return None;
    }
    let mut out = [0u8; 64];

    #[cfg(target_arch = "wasm32")]
    let ok = unsafe {
        sys::host_vrf_lagrange_combine(
            epoch_pk.as_ptr() as i32,
            alpha.as_ptr() as i32,
            alpha.len() as i32,
            packed_36b_shares.as_ptr() as i32,
            shares_count as i32,
            out.as_mut_ptr() as i32,
        ) == 1
    };

    #[cfg(not(target_arch = "wasm32"))]
    let ok = mock_crypto::lagrange_combine_packed(
        epoch_pk,
        alpha,
        packed_36b_shares,
        shares_count,
        &mut out,
    );

    if !ok {
        return None;
    }
    let mut gamma = [0u8; 32];
    let mut rnd = [0u8; 32];
    gamma.copy_from_slice(&out[0..32]);
    rnd.copy_from_slice(&out[32..64]);
    Some((gamma, rnd))
}

/// Homomorphic Vector ElGamal linear combination `s1 * P1 + s2 * P2` in prime-order `<B>`.
pub fn ec_elgamal_lincomb(
    s1: &[u8; 32],
    p1: &[u8; 32],
    s2: &[u8; 32],
    p2: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    #[cfg(target_arch = "wasm32")]
    let ok = unsafe {
        sys::host_ec_elgamal_lincomb(
            s1.as_ptr() as i32,
            p1.as_ptr() as i32,
            s2.as_ptr() as i32,
            p2.as_ptr() as i32,
            out.as_mut_ptr() as i32,
        ) == 1
    };
    #[cfg(not(target_arch = "wasm32"))]
    let ok = match mock_crypto::elgamal_lincomb(s1, p1, s2, p2) {
        Some(r) => {
            out = r;
            true
        }
        None => false,
    };
    if ok {
        Some(out)
    } else {
        None
    }
}

/// General Chaum-Pedersen DLEQ verifier (`log_{g1}(y1) == log_{g2}(y2)`).
pub fn ec_dleq_verify(
    g1: &[u8; 32],
    y1: &[u8; 32],
    g2: &[u8; 32],
    y2: &[u8; 32],
    ctx: &[u8],
    proof_64: &[u8; 64],
) -> bool {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_ec_dleq_verify(
            g1.as_ptr() as i32,
            y1.as_ptr() as i32,
            g2.as_ptr() as i32,
            y2.as_ptr() as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof_64.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_dleq_bytes(g1, y1, g2, y2, ctx, proof_64)
    }
}

/// Homomorphic addition of two 64-byte ElGamal ciphertexts: `Enc(a) + Enc(b) = Enc(a + b)`.
pub fn he_add_ciphertexts(ca: &[u8; 64], cb: &[u8; 64]) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    #[cfg(target_arch = "wasm32")]
    let ok = unsafe {
        sys::host_he_add_ciphertexts(
            ca.as_ptr() as i32,
            cb.as_ptr() as i32,
            out.as_mut_ptr() as i32,
        ) == 1
    };
    #[cfg(not(target_arch = "wasm32"))]
    let ok = match mock_crypto::he_add_ciphertexts(ca, cb) {
        Some(r) => {
            out = r;
            true
        }
        None => false,
    };
    if ok {
        Some(out)
    } else {
        None
    }
}

/// Homomorphic non-negative scalar scaling `weight * Enc(m) = Enc(weight * m)`.
pub fn he_scale_ciphertext(ct: &[u8; 64], weight: u64) -> Option<[u8; 64]> {
    if weight > (i64::MAX as u64) {
        return None;
    }
    let mut out = [0u8; 64];
    #[cfg(target_arch = "wasm32")]
    let ok = unsafe {
        sys::host_he_scale_ciphertext(
            ct.as_ptr() as i32,
            weight as i64,
            out.as_mut_ptr() as i32,
        ) == 1
    };
    #[cfg(not(target_arch = "wasm32"))]
    let ok = match mock_crypto::he_scale_ciphertext(ct, weight) {
        Some(r) => {
            out = r;
            true
        }
        None => false,
    };
    if ok {
        Some(out)
    } else {
        None
    }
}

/// Verifies a 128-byte Cramer-Damgård-Schoenmakers 1-of-2 Disjunctive Schnorr ZK proof
/// `[c0_32, z0_32, c1_32, z1_32]` that `ct_64` encrypts strictly `0` OR `1` under `pk_32`.
pub fn he_verify_zero_or_one(
    pk_32: &[u8; 32],
    ct_64: &[u8; 64],
    ctx: &[u8],
    proof_128: &[u8; 128],
) -> bool {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_he_verify_zero_or_one(
            pk_32.as_ptr() as i32,
            ct_64.as_ptr() as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof_128.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_he_zero_or_one(pk_32, ct_64, ctx, proof_128)
    }
}

/// Verifies a 96-byte Schnorr Ciphertext Proof of Knowledge `[c_32, zm_32, zr_32]`.
pub fn he_verify_pok(
    pk_32: &[u8; 32],
    ct_64: &[u8; 64],
    ctx: &[u8],
    proof_96: &[u8; 96],
) -> bool {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_he_verify_pok(
            pk_32.as_ptr() as i32,
            ct_64.as_ptr() as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof_96.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_he_ciphertext_pok(pk_32, ct_64, ctx, proof_96)
    }
}

/// Verifies validator `j`'s partial ElGamal decryption share `(d_j_32, proof_64)`.
pub fn he_verify_decryption_share(
    share_pk: &[u8; 32],
    c1: &[u8; 32],
    d_j: &[u8; 32],
    ctx: &[u8],
    proof_64: &[u8; 64],
) -> bool {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        sys::host_he_verify_decryption_share(
            share_pk.as_ptr() as i32,
            c1.as_ptr() as i32,
            d_j.as_ptr() as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
            proof_64.as_ptr() as i32,
        ) == 1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mock_crypto::verify_validator_decryption_share(share_pk, c1, d_j, ctx, proof_64)
    }
}

/// Lagrange-combines `shares_count` partial decryption points (`packed_36b_shares`: `[idx_u32_be || D_i_32]`)
/// into `(D_point_32, M_point_32, Option<recovered_u64>)`.
pub fn he_lagrange_decrypt(
    c1: &[u8; 32],
    c2: &[u8; 32],
    packed_36b_shares: &[u8],
    shares_count: usize,
    max_val: u64,
) -> Option<([u8; 32], [u8; 32], Option<u64>)> {
    if shares_count > MAX_VRF_VALIDATORS
        || packed_36b_shares.len() < shares_count * 36
        || max_val > (i64::MAX as u64)
    {
        return None;
    }
    let mut out = [0u8; 72];
    #[cfg(target_arch = "wasm32")]
    let rc = unsafe {
        sys::host_he_lagrange_decrypt(
            c1.as_ptr() as i32,
            c2.as_ptr() as i32,
            packed_36b_shares.as_ptr() as i32,
            shares_count as i32,
            max_val as i64,
            out.as_mut_ptr() as i32,
        )
    };
    #[cfg(not(target_arch = "wasm32"))]
    let rc = mock_crypto::lagrange_decrypt_packed(
        c1,
        c2,
        packed_36b_shares,
        shares_count,
        max_val,
        &mut out,
    );

    if rc <= 0 {
        return None;
    }
    let mut d_32 = [0u8; 32];
    let mut m_32 = [0u8; 32];
    d_32.copy_from_slice(&out[0..32]);
    m_32.copy_from_slice(&out[32..64]);
    let val = if rc == 1 {
        let mut vb = [0u8; 8];
        vb.copy_from_slice(&out[64..72]);
        Some(u64::from_be_bytes(vb))
    } else {
        None
    };
    Some((d_32, m_32, val))
}

// ============================================================================
// Confidential Category Roll-Up, Range-Proof & Stealth Non-Insider Helpers
// ============================================================================

/// Bit-width of individual confidential line-item range proofs (`0 .. 16,777,215` units).
pub const CONF_RANGE_BITS: usize = 24;
/// Byte stride per proven binary bit (`[bit_ct_64 || cds_or01_proof_128]`).
pub const CONF_BIT_PROOF_STRIDE: usize = 192;
/// Total byte length of a 24-bit non-negative range proof (`24 * 192 = 4,608` bytes).
pub const CONF_RANGE_PROOF_BYTES: usize = CONF_RANGE_BITS * CONF_BIT_PROOF_STRIDE;
/// Default minimum slot count (with zero-value dummy commitment padding) per confidential roll-up.
pub const CONF_MIN_PADDED_SLOTS: usize = 4;

/// Subtracts two 64-byte ElGamal ciphertexts homomorphically: `Enc(a) - Enc(b) = Enc(a - b)`.
pub fn he_sub_ciphertexts(ca: &[u8; 64], cb: &[u8; 64]) -> Option<[u8; 64]> {
    let mut ca1 = [0u8; 32];
    let mut ca2 = [0u8; 32];
    let mut cb1 = [0u8; 32];
    let mut cb2 = [0u8; 32];
    ca1.copy_from_slice(&ca[0..32]);
    ca2.copy_from_slice(&ca[32..64]);
    cb1.copy_from_slice(&cb[0..32]);
    cb2.copy_from_slice(&cb[32..64]);

    let d1 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &ca1, &SCALAR_MINUS_ONE_BYTES, &cb1)?;
    let d2 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &ca2, &SCALAR_MINUS_ONE_BYTES, &cb2)?;
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&d1);
    out[32..64].copy_from_slice(&d2);
    Some(out)
}

/// Verifies a `4,608`-byte 24-bit binary-decomposition range proof under `pk_32` and
/// deterministically reconstructs the 64-byte ElGamal ciphertext `C_slot = ∑ 2^b * C_b`,
/// guaranteeing `0 <= value < 2^24` (`16,777,216`) without modulo-`ℓ` negative wrap-around.
#[inline(never)]
pub fn verify_he_range_u24(
    pk_32: &[u8; 32],
    ctx_prefix: &[u8],
    slot_idx: u32,
    packed_4608: &[u8],
) -> Option<[u8; 64]> {
    if packed_4608.len() != CONF_RANGE_PROOF_BYTES || ctx_prefix.len() > 192 {
        return None;
    }
    const TAG: &[u8] = b"SLX_CONF_BIT01_V1:";
    let mut ctx_buf = [0u8; 18 + 192 + 5];
    ctx_buf[0..18].copy_from_slice(TAG);
    let p_end = 18 + ctx_prefix.len();
    ctx_buf[18..p_end].copy_from_slice(ctx_prefix);
    ctx_buf[p_end..p_end + 4].copy_from_slice(&slot_idx.to_be_bytes());
    let ctx_len = p_end + 5;

    let mut bit_cts = [[0u8; 64]; CONF_RANGE_BITS];
    let mut b = 0usize;
    while b < CONF_RANGE_BITS {
        let off = b * CONF_BIT_PROOF_STRIDE;
        bit_cts[b].copy_from_slice(&packed_4608[off..off + 64]);
        let mut proof_128 = [0u8; 128];
        proof_128.copy_from_slice(&packed_4608[off + 64..off + 192]);
        ctx_buf[p_end + 4] = b as u8;
        if !he_verify_zero_or_one(pk_32, &bit_cts[b], &ctx_buf[..ctx_len], &proof_128) {
            return None;
        }
        b += 1;
    }

    // Reconstruct `C_slot = ∑_{b=0}^{23} 2^b * bit_cts[b]` via Horner's method.
    let mut acc = bit_cts[CONF_RANGE_BITS - 1];
    let mut rev = CONF_RANGE_BITS - 1;
    while rev > 0 {
        rev -= 1;
        acc = he_scale_ciphertext(&acc, 2)?;
        acc = he_add_ciphertexts(&acc, &bit_cts[rev])?;
    }
    Some(acc)
}

/// Verifies a 64-byte Chaum-Pedersen DLEQ proof that `c_sum_64 = (R * B, public_amount * B + R * pk_32)`
/// encrypts the exact integer `public_amount` under `pk_32` without revealing `R`.
#[inline(never)]
pub fn verify_he_sum_equals_u64(
    pk_32: &[u8; 32],
    c_sum_64: &[u8; 64],
    public_amount: u64,
    sum_ctx: &[u8],
    dleq_proof_64: &[u8; 64],
) -> bool {
    let mut c1 = [0u8; 32];
    let mut c2 = [0u8; 32];
    c1.copy_from_slice(&c_sum_64[0..32]);
    c2.copy_from_slice(&c_sum_64[32..64]);

    let pub_pt = if public_amount == 0 {
        IDENTITY_POINT_BYTES
    } else {
        let mut s_pub = [0u8; 32];
        s_pub[0..8].copy_from_slice(&public_amount.to_le_bytes());
        let s_zero = [0u8; 32];
        let Some(p) =
            ec_elgamal_lincomb(&s_pub, &ED25519_BASEPOINT_BYTES, &s_zero, &IDENTITY_POINT_BYTES)
        else {
            return false;
        };
        p
    };

    let Some(m_diff) =
        ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &c2, &SCALAR_MINUS_ONE_BYTES, &pub_pt)
    else {
        return false;
    };

    if c1 == IDENTITY_POINT_BYTES {
        return m_diff == IDENTITY_POINT_BYTES && *dleq_proof_64 == [0u8; 64];
    }
    ec_dleq_verify(
        &ED25519_BASEPOINT_BYTES,
        &c1,
        pk_32,
        &m_diff,
        sum_ctx,
        dleq_proof_64,
    )
}

/// Verifies a 64-byte prime-order `Edwards25519` Schnorr knowledge signature (`pubkey = secret * base`)
/// over `msg_ctx` via diagonal Chaum-Pedersen DLEQ (`log_base(pubkey) == log_base(pubkey)`).
pub fn verify_ed25519_schnorr(
    base_32: &[u8; 32],
    pubkey_32: &[u8; 32],
    msg_ctx: &[u8],
    sig_64: &[u8; 64],
) -> bool {
    if *base_32 == [0u8; 32]
        || *base_32 == IDENTITY_POINT_BYTES
        || *pubkey_32 == [0u8; 32]
        || *pubkey_32 == IDENTITY_POINT_BYTES
    {
        return false;
    }
    ec_dleq_verify(base_32, pubkey_32, base_32, pubkey_32, msg_ctx, sig_64)
}

/// Verifies an `IAS 24` Stealth Counterparty Non-Insider Proof:
/// Given `h_base_32 = ρ * B` and `p_blind_32 = ρ * PK_client` (`ρ != 0`), checks for every active
/// Charter insider key `PK_j` that `Q_j = ρ * PK_j` (proven via DLEQ) satisfies `Q_j != p_blind_32`,
/// mathematically proving `PK_client != PK_j` without revealing `PK_client`.
#[inline(never)]
pub fn verify_stealth_non_insider(
    h_base_32: &[u8; 32],
    p_blind_32: &[u8; 32],
    insider_pks: &[[u8; 32]],
    ctx_prefix: &[u8],
    proof_blob: &[u8],
) -> bool {
    if *h_base_32 == [0u8; 32]
        || *h_base_32 == IDENTITY_POINT_BYTES
        || *p_blind_32 == [0u8; 32]
        || *p_blind_32 == IDENTITY_POINT_BYTES
        || ctx_prefix.len() > 192
        || proof_blob.len() != insider_pks.len() * 96
    {
        return false;
    }
    const TAG: &[u8] = b"SLX_IAS24_NEQ_V1:";
    let mut ctx_buf = [0u8; 17 + 192 + 4];
    ctx_buf[0..17].copy_from_slice(TAG);
    let p_end = 17 + ctx_prefix.len();
    ctx_buf[17..p_end].copy_from_slice(ctx_prefix);
    let ctx_len = p_end + 4;

    let mut j = 0usize;
    while j < insider_pks.len() {
        let pk_j = &insider_pks[j];
        if *pk_j != [0u8; 32] && *pk_j != IDENTITY_POINT_BYTES {
            let off = j * 96;
            let mut q_j = [0u8; 32];
            let mut dleq_j = [0u8; 64];
            q_j.copy_from_slice(&proof_blob[off..off + 32]);
            dleq_j.copy_from_slice(&proof_blob[off + 32..off + 96]);
            if q_j == *p_blind_32 || q_j == IDENTITY_POINT_BYTES {
                return false;
            }
            ctx_buf[p_end..p_end + 4].copy_from_slice(&(j as u32).to_be_bytes());
            if !ec_dleq_verify(
                &ED25519_BASEPOINT_BYTES,
                h_base_32,
                pk_j,
                &q_j,
                &ctx_buf[..ctx_len],
                &dleq_j,
            ) {
                return false;
            }
        }
        j += 1;
    }
    true
}

#[cfg(not(target_arch = "wasm32"))]
pub mod mock_crypto {
    use super::{dkg_deal_byte_len, min_safe_validator_threshold, ActiveValidator, MAX_VRF_VALIDATORS};
    use crate::keccak::keccak256;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE};
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    pub use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::{Identity, IsIdentity};
    pub use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha512};
    use std::cell::RefCell;

    thread_local! {
        static MOCK_VALIDATORS: RefCell<Vec<ActiveValidator>> = const { RefCell::new(Vec::new()) };
    }

    /// Configure the simulated consensus `Full` validator set for native `cargo test` runs.
    /// Automatically sorts and deduplicates by 32-byte Ed25519 public key ascending (matching `WasmtimeAdapter`).
    pub fn set_mock_validators(entries: &[([u8; 20], [u8; 32])]) {
        let mut clean: Vec<ActiveValidator> = entries
            .iter()
            .filter(|(_, pk)| decode_prime_order_point(pk).is_some())
            .map(|(address, pubkey)| ActiveValidator {
                address: *address,
                pubkey: *pubkey,
            })
            .collect();
        clean.sort_by(|a, b| a.pubkey.cmp(&b.pubkey).then_with(|| a.address.cmp(&b.address)));
        clean.dedup_by(|a, b| a.pubkey == b.pubkey);
        clean.truncate(MAX_VRF_VALIDATORS);
        MOCK_VALIDATORS.with(|v| *v.borrow_mut() = clean);
    }

    pub fn compute_validator_set_hash(threshold: usize, sorted_pks: &[[u8; 32]]) -> [u8; 32] {
        let mut pre = Vec::with_capacity(14 + 8 + sorted_pks.len() * 32);
        pre.extend_from_slice(b"SLX_VAL_SET_V1");
        pre.extend_from_slice(&(sorted_pks.len() as u32).to_be_bytes());
        pre.extend_from_slice(&(threshold as u32).to_be_bytes());
        for pk in sorted_pks {
            pre.extend_from_slice(pk);
        }
        keccak256(&pre)
    }

    pub(crate) fn fill_active_validators_blob(out: &mut [u8]) -> i32 {
        MOCK_VALIDATORS.with(|v| {
            let entries = v.borrow();
            let n = entries.len();
            let threshold = min_safe_validator_threshold(n);
            let pks: Vec<[u8; 32]> = entries.iter().map(|e| e.pubkey).collect();
            let set_hash = compute_validator_set_hash(threshold, &pks);
            let need = 40 + n * 52;
            if out.len() < need {
                return -101;
            }
            out[0..4].copy_from_slice(&(n as u32).to_be_bytes());
            out[4..8].copy_from_slice(&(threshold as u32).to_be_bytes());
            out[8..40].copy_from_slice(&set_hash);
            for (i, e) in entries.iter().enumerate() {
                let b = 40 + i * 52;
                out[b..b + 20].copy_from_slice(&e.address);
                out[b + 20..b + 52].copy_from_slice(&e.pubkey);
            }
            n as i32
        })
    }

    pub fn decode_prime_order_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        let pt = CompressedEdwardsY(*bytes).decompress()?;
        if pt.is_identity() || !pt.is_torsion_free() || pt.compress().as_bytes() != bytes {
            return None;
        }
        Some(pt)
    }

    pub fn decode_torsion_free_or_identity(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        let pt = CompressedEdwardsY(*bytes).decompress()?;
        if !pt.is_torsion_free() || pt.compress().as_bytes() != bytes {
            return None;
        }
        Some(pt)
    }

    pub fn hash_to_curve(alpha: &[u8]) -> EdwardsPoint {
        let len_be = (alpha.len() as u64).to_be_bytes();
        for ctr in 0u8..=255 {
            let mut h = Sha512::new();
            h.update(b"SLX_VM_VRF_H2C_V1");
            h.update(len_be);
            h.update(alpha);
            h.update([ctr]);
            let digest = h.finalize();
            let mut cand = [0u8; 32];
            cand.copy_from_slice(&digest[0..32]);
            cand[31] &= 0x7f;
            if let Some(raw_pt) = CompressedEdwardsY(cand).decompress() {
                let cleared = raw_pt.mul_by_cofactor();
                if !cleared.is_identity() {
                    return cleared;
                }
            }
        }
        ED25519_BASEPOINT_POINT
    }

    fn dleq_challenge(
        g1: &EdwardsPoint,
        y1: &EdwardsPoint,
        g2: &EdwardsPoint,
        y2: &EdwardsPoint,
        r1: &EdwardsPoint,
        r2: &EdwardsPoint,
        aux_ctx: &[u8],
    ) -> Scalar {
        let mut h = Sha512::new();
        h.update(b"SLX_VM_DLEQ_CHAL_V1");
        h.update(g1.compress().as_bytes());
        h.update(y1.compress().as_bytes());
        h.update(g2.compress().as_bytes());
        h.update(y2.compress().as_bytes());
        h.update(r1.compress().as_bytes());
        h.update(r2.compress().as_bytes());
        h.update((aux_ctx.len() as u64).to_be_bytes());
        h.update(aux_ctx);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    pub fn prove_dleq(
        secret: &Scalar,
        g1: &EdwardsPoint,
        y1: &EdwardsPoint,
        g2: &EdwardsPoint,
        y2: &EdwardsPoint,
        aux_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> [u8; 64] {
        let mut kh = Sha512::new();
        kh.update(b"SLX_VM_DLEQ_NONCE_V1");
        kh.update(secret.as_bytes());
        kh.update(g1.compress().as_bytes());
        kh.update(y1.compress().as_bytes());
        kh.update(g2.compress().as_bytes());
        kh.update(y2.compress().as_bytes());
        kh.update((aux_ctx.len() as u64).to_be_bytes());
        kh.update(aux_ctx);
        kh.update(entropy_32);
        let k = Scalar::from_bytes_mod_order_wide(&kh.finalize().into());
        let r1 = k * g1;
        let r2 = k * g2;
        let c = dleq_challenge(g1, y1, g2, y2, &r1, &r2, aux_ctx);
        let z = k + c * secret;
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(c.as_bytes());
        out[32..64].copy_from_slice(z.as_bytes());
        out
    }

    pub fn verify_dleq(
        g1: &EdwardsPoint,
        y1: &EdwardsPoint,
        g2: &EdwardsPoint,
        y2: &EdwardsPoint,
        aux_ctx: &[u8],
        proof_64: &[u8; 64],
    ) -> bool {
        let mut cb = [0u8; 32];
        let mut zb = [0u8; 32];
        cb.copy_from_slice(&proof_64[0..32]);
        zb.copy_from_slice(&proof_64[32..64]);
        let Some(c) = Option::<Scalar>::from(Scalar::from_canonical_bytes(cb)) else {
            return false;
        };
        let Some(z) = Option::<Scalar>::from(Scalar::from_canonical_bytes(zb)) else {
            return false;
        };
        let r1 = z * g1 - c * y1;
        let r2 = z * g2 - c * y2;
        c == dleq_challenge(g1, y1, g2, y2, &r1, &r2, aux_ctx)
    }

    pub(crate) fn verify_dleq_bytes(
        g1_b: &[u8; 32],
        y1_b: &[u8; 32],
        g2_b: &[u8; 32],
        y2_b: &[u8; 32],
        ctx: &[u8],
        proof_64: &[u8; 64],
    ) -> bool {
        let (Some(g1), Some(y1), Some(g2), Some(y2)) = (
            decode_prime_order_point(g1_b),
            decode_torsion_free_or_identity(y1_b),
            decode_prime_order_point(g2_b),
            decode_torsion_free_or_identity(y2_b),
        ) else {
            return false;
        };
        verify_dleq(&g1, &y1, &g2, &y2, ctx, proof_64)
    }

    pub fn elgamal_lincomb(
        s1_bytes: &[u8; 32],
        p1_bytes: &[u8; 32],
        s2_bytes: &[u8; 32],
        p2_bytes: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let s1 = Option::<Scalar>::from(Scalar::from_canonical_bytes(*s1_bytes))?;
        let s2 = Option::<Scalar>::from(Scalar::from_canonical_bytes(*s2_bytes))?;
        let p1 = decode_torsion_free_or_identity(p1_bytes)?;
        let p2 = decode_torsion_free_or_identity(p2_bytes)?;
        Some((s1 * p1 + s2 * p2).compress().to_bytes())
    }

    fn dkg_share_mask(
        set_hash: &[u8; 32],
        dealer_idx: usize,
        recipient_idx: usize,
        ephem_pub: &[u8; 32],
        recipient_pk: &[u8; 32],
        shared_pt: &EdwardsPoint,
    ) -> Scalar {
        let mut h = Sha512::new();
        h.update(b"SLX_DKG_SHARE_MASK_V1");
        h.update(set_hash);
        h.update(&(dealer_idx as u32).to_be_bytes());
        h.update(&(recipient_idx as u32).to_be_bytes());
        h.update(ephem_pub);
        h.update(recipient_pk);
        h.update(shared_pt.compress().as_bytes());
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    fn dkg_deal_auth_context(
        set_hash: &[u8; 32],
        dealer_idx: usize,
        threshold: usize,
        body_without_sigs: &[u8],
    ) -> [u8; 32] {
        let mut pre = Vec::with_capacity(21 + 32 + 8 + body_without_sigs.len());
        pre.extend_from_slice(b"SLX_DKG_DEAL_AUTH_V1:");
        pre.extend_from_slice(set_hash);
        pre.extend_from_slice(&(dealer_idx as u32).to_be_bytes());
        pre.extend_from_slice(&(threshold as u32).to_be_bytes());
        pre.extend_from_slice(body_without_sigs);
        keccak256(&pre)
    }

    fn dkg_c0_pok_context(set_hash: &[u8; 32], dealer_idx: usize, c0_bytes: &[u8; 32]) -> [u8; 32] {
        let mut pre = [0u8; 87];
        pre[0..19].copy_from_slice(b"SLX_DKG_C0_POK_V1::");
        pre[19..51].copy_from_slice(set_hash);
        pre[51..55].copy_from_slice(&(dealer_idx as u32).to_be_bytes());
        pre[55..87].copy_from_slice(c0_bytes);
        keccak256(&pre)
    }

    fn eval_poly(coeffs: &[Scalar], x: u64) -> Scalar {
        let x_sc = Scalar::from(x);
        let mut acc = Scalar::ZERO;
        for coeff in coeffs.iter().rev() {
            acc = acc * x_sc + coeff;
        }
        acc
    }

    pub fn eval_commitment_poly(commitments: &[EdwardsPoint], recipient_idx: usize) -> EdwardsPoint {
        let x_sc = Scalar::from((recipient_idx + 1) as u64);
        let mut acc = EdwardsPoint::identity();
        for c_m in commitments.iter().rev() {
            acc = acc * x_sc + c_m;
        }
        acc
    }

    pub fn create_validator_dkg_deal(
        signing_key: &SigningKey,
        set_hash: &[u8; 32],
        dealer_idx: usize,
        threshold: usize,
        validator_pks: &[[u8; 32]],
        entropy_32: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let n = validator_pks.len();
        if threshold == 0 || threshold > n || dealer_idx >= n || n > MAX_VRF_VALIDATORS {
            return None;
        }
        let my_pk_bytes = signing_key.verifying_key().to_bytes();
        if validator_pks[dealer_idx] != my_pk_bytes {
            return None;
        }
        let my_pk_pt = decode_prime_order_point(&my_pk_bytes)?;
        let my_secret = signing_key.to_scalar();
        let mut recipient_pts = Vec::with_capacity(n);
        for pk_b in validator_pks {
            recipient_pts.push(decode_prime_order_point(pk_b)?);
        }
        let derive_nonzero_scalar = |tag: u8, idx: u32| -> Scalar {
            for ctr in 0u8..=255 {
                let mut h = Sha512::new();
                h.update(b"SLX_DKG_POLY_DERIVE_V1");
                h.update(my_secret.as_bytes());
                h.update(set_hash);
                h.update(&(dealer_idx as u32).to_be_bytes());
                h.update(entropy_32);
                h.update([tag, ctr]);
                h.update(idx.to_be_bytes());
                let sc = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
                if sc != Scalar::ZERO {
                    return sc;
                }
            }
            Scalar::ONE
        };
        let mut coeffs = Vec::with_capacity(threshold);
        for m in 0..threshold {
            coeffs.push(derive_nonzero_scalar(1, m as u32));
        }
        let ephem_d = derive_nonzero_scalar(2, 0);
        let ephem_pub_bytes = (&ephem_d * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let body_len = 32 + (threshold + n) * 32;
        let mut out = Vec::with_capacity(body_len + 128);
        out.extend_from_slice(&ephem_pub_bytes);

        let mut c0_bytes = [0u8; 32];
        let mut c0_pt = ED25519_BASEPOINT_POINT;
        for (m, a_m) in coeffs.iter().enumerate() {
            let cm_pt = a_m * ED25519_BASEPOINT_TABLE;
            let cm_b = cm_pt.compress().to_bytes();
            if m == 0 {
                c0_bytes = cm_b;
                c0_pt = cm_pt;
            }
            out.extend_from_slice(&cm_b);
        }
        for j in 0..n {
            let f_xj = eval_poly(&coeffs, (j + 1) as u64);
            let shared = ephem_d * recipient_pts[j];
            let mask = dkg_share_mask(
                set_hash,
                dealer_idx,
                j,
                &ephem_pub_bytes,
                &validator_pks[j],
                &shared,
            );
            out.extend_from_slice((f_xj + mask).as_bytes());
        }
        let base_pt = ED25519_BASEPOINT_POINT;
        let auth_ctx = dkg_deal_auth_context(set_hash, dealer_idx, threshold, &out[..body_len]);
        let auth_sig = prove_dleq(&my_secret, &base_pt, &my_pk_pt, &base_pt, &my_pk_pt, &auth_ctx, entropy_32);
        let pok_ctx = dkg_c0_pok_context(set_hash, dealer_idx, &c0_bytes);
        let c0_pok = prove_dleq(&coeffs[0], &base_pt, &c0_pt, &base_pt, &c0_pt, &pok_ctx, entropy_32);
        out.extend_from_slice(&auth_sig);
        out.extend_from_slice(&c0_pok);
        Some(out)
    }

    pub fn verify_validator_dkg_deal(
        set_hash: &[u8; 32],
        dealer_idx: usize,
        threshold: usize,
        validator_pks: &[[u8; 32]],
        deal: &[u8],
    ) -> bool {
        let n = validator_pks.len();
        if threshold == 0
            || threshold > n
            || dealer_idx >= n
            || n > MAX_VRF_VALIDATORS
            || deal.len() != dkg_deal_byte_len(threshold, n)
        {
            return false;
        }
        let Some(dealer_pk) = decode_prime_order_point(&validator_pks[dealer_idx]) else {
            return false;
        };
        let mut ephem_b = [0u8; 32];
        ephem_b.copy_from_slice(&deal[0..32]);
        if decode_prime_order_point(&ephem_b).is_none() {
            return false;
        }
        let mut c0_b = [0u8; 32];
        let mut c0_pt = ED25519_BASEPOINT_POINT;
        for m in 0..threshold {
            let off = 32 + m * 32;
            let mut cb = [0u8; 32];
            cb.copy_from_slice(&deal[off..off + 32]);
            let Some(pt) = decode_prime_order_point(&cb) else {
                return false;
            };
            if m == 0 {
                c0_b = cb;
                c0_pt = pt;
            }
        }
        let shares_base = 32 + threshold * 32;
        for j in 0..n {
            let off = shares_base + j * 32;
            let mut sb = [0u8; 32];
            sb.copy_from_slice(&deal[off..off + 32]);
            if Option::<Scalar>::from(Scalar::from_canonical_bytes(sb)).is_none() {
                return false;
            }
        }
        let body_len = 32 + (threshold + n) * 32;
        let mut auth_sig = [0u8; 64];
        let mut c0_pok = [0u8; 64];
        auth_sig.copy_from_slice(&deal[body_len..body_len + 64]);
        c0_pok.copy_from_slice(&deal[body_len + 64..body_len + 128]);
        let base_pt = ED25519_BASEPOINT_POINT;
        let auth_ctx = dkg_deal_auth_context(set_hash, dealer_idx, threshold, &deal[..body_len]);
        if !verify_dleq(&base_pt, &dealer_pk, &base_pt, &dealer_pk, &auth_ctx, &auth_sig) {
            return false;
        }
        let pok_ctx = dkg_c0_pok_context(set_hash, dealer_idx, &c0_b);
        verify_dleq(&base_pt, &c0_pt, &base_pt, &c0_pt, &pok_ctx, &c0_pok)
    }

    pub fn decrypt_validator_dkg_share(
        recipient_signing_key: &SigningKey,
        set_hash: &[u8; 32],
        dealer_idx: usize,
        recipient_idx: usize,
        threshold: usize,
        validator_pks: &[[u8; 32]],
        deal: &[u8],
        entropy_32: &[u8; 32],
    ) -> Result<Scalar, ([u8; 32], [u8; 64])> {
        let n = validator_pks.len();
        if deal.len() != dkg_deal_byte_len(threshold, n) || recipient_idx >= n {
            return Err(([0u8; 32], [0u8; 64]));
        }
        let mut ephem_b = [0u8; 32];
        ephem_b.copy_from_slice(&deal[0..32]);
        let Some(ephem_pt) = decode_prime_order_point(&ephem_b) else {
            return Err(([0u8; 32], [0u8; 64]));
        };
        let mut commitments = Vec::with_capacity(threshold);
        for m in 0..threshold {
            let off = 32 + m * 32;
            let mut cb = [0u8; 32];
            cb.copy_from_slice(&deal[off..off + 32]);
            let Some(pt) = decode_prime_order_point(&cb) else {
                return Err(([0u8; 32], [0u8; 64]));
            };
            commitments.push(pt);
        }
        let share_off = 32 + threshold * 32 + recipient_idx * 32;
        let mut enc_b = [0u8; 32];
        enc_b.copy_from_slice(&deal[share_off..share_off + 32]);
        let Some(enc_sc) = Option::<Scalar>::from(Scalar::from_canonical_bytes(enc_b)) else {
            return Err(([0u8; 32], [0u8; 64]));
        };
        let my_secret = recipient_signing_key.to_scalar();
        let shared_pt = my_secret * ephem_pt;
        let mask = dkg_share_mask(
            set_hash,
            dealer_idx,
            recipient_idx,
            &ephem_b,
            &validator_pks[recipient_idx],
            &shared_pt,
        );
        let f_val = enc_sc - mask;
        if (&f_val * ED25519_BASEPOINT_TABLE) == eval_commitment_poly(&commitments, recipient_idx) {
            return Ok(f_val);
        }
        let my_pk_pt = &my_secret * ED25519_BASEPOINT_TABLE;
        let mut disp_ctx = [0u8; 56];
        disp_ctx[0..16].copy_from_slice(b"SLX_DKG_DISP_V1:");
        disp_ctx[16..48].copy_from_slice(set_hash);
        disp_ctx[48..52].copy_from_slice(&(dealer_idx as u32).to_be_bytes());
        disp_ctx[52..56].copy_from_slice(&(recipient_idx as u32).to_be_bytes());
        let proof = prove_dleq(
            &my_secret,
            &ED25519_BASEPOINT_POINT,
            &my_pk_pt,
            &ephem_pt,
            &shared_pt,
            &disp_ctx,
            entropy_32,
        );
        Err((shared_pt.compress().to_bytes(), proof))
    }

    pub fn verify_dkg_share_dispute(
        set_hash: &[u8; 32],
        dealer_idx: usize,
        accuser_idx: usize,
        threshold: usize,
        validator_pks: &[[u8; 32]],
        deal: &[u8],
        shared_pt_bytes: &[u8; 32],
        dleq_proof_64: &[u8; 64],
    ) -> bool {
        let n = validator_pks.len();
        if deal.len() != dkg_deal_byte_len(threshold, n) || dealer_idx >= n || accuser_idx >= n {
            return false;
        }
        let Some(accuser_pk) = decode_prime_order_point(&validator_pks[accuser_idx]) else {
            return false;
        };
        let Some(shared_pt) = decode_torsion_free_or_identity(shared_pt_bytes) else {
            return false;
        };
        let mut ephem_b = [0u8; 32];
        ephem_b.copy_from_slice(&deal[0..32]);
        let Some(ephem_pt) = decode_prime_order_point(&ephem_b) else {
            return false;
        };
        let mut disp_ctx = [0u8; 56];
        disp_ctx[0..16].copy_from_slice(b"SLX_DKG_DISP_V1:");
        disp_ctx[16..48].copy_from_slice(set_hash);
        disp_ctx[48..52].copy_from_slice(&(dealer_idx as u32).to_be_bytes());
        disp_ctx[52..56].copy_from_slice(&(accuser_idx as u32).to_be_bytes());
        if !verify_dleq(
            &ED25519_BASEPOINT_POINT,
            &accuser_pk,
            &ephem_pt,
            &shared_pt,
            &disp_ctx,
            dleq_proof_64,
        ) {
            return false;
        }
        let mut commitments = Vec::with_capacity(threshold);
        for m in 0..threshold {
            let off = 32 + m * 32;
            let mut cb = [0u8; 32];
            cb.copy_from_slice(&deal[off..off + 32]);
            let Some(pt) = decode_prime_order_point(&cb) else {
                return false;
            };
            commitments.push(pt);
        }
        let share_off = 32 + threshold * 32 + accuser_idx * 32;
        let mut enc_b = [0u8; 32];
        enc_b.copy_from_slice(&deal[share_off..share_off + 32]);
        let Some(enc_sc) = Option::<Scalar>::from(Scalar::from_canonical_bytes(enc_b)) else {
            return false;
        };
        let mask = dkg_share_mask(
            set_hash,
            dealer_idx,
            accuser_idx,
            &ephem_b,
            &validator_pks[accuser_idx],
            &shared_pt,
        );
        let f_val = enc_sc - mask;
        (&f_val * ED25519_BASEPOINT_TABLE) != eval_commitment_poly(&commitments, accuser_idx)
    }

    pub(crate) fn derive_epoch_keys_packed(
        threshold: usize,
        val_count: usize,
        packed_deals: &[u8],
        deals_count: usize,
        deal_stride: usize,
        out_buf: &mut [[u8; 32]; MAX_VRF_VALIDATORS + 1],
    ) -> bool {
        let expected_len = dkg_deal_byte_len(threshold, val_count);
        if deal_stride < expected_len {
            return false;
        }
        let mut parsed_comms = Vec::with_capacity(deals_count);
        let mut group_pk = EdwardsPoint::identity();
        for i in 0..deals_count {
            let d = &packed_deals[i * deal_stride..i * deal_stride + expected_len];
            let mut comms = Vec::with_capacity(threshold);
            for m in 0..threshold {
                let off = 32 + m * 32;
                let mut cb = [0u8; 32];
                cb.copy_from_slice(&d[off..off + 32]);
                let Some(pt) = decode_prime_order_point(&cb) else {
                    return false;
                };
                if m == 0 {
                    group_pk += pt;
                }
                comms.push(pt);
            }
            parsed_comms.push(comms);
        }
        if group_pk.is_identity() {
            return false;
        }
        out_buf[0] = group_pk.compress().to_bytes();
        for j in 0..val_count {
            let mut pk_j = EdwardsPoint::identity();
            for comms in &parsed_comms {
                pk_j += eval_commitment_poly(comms, j);
            }
            if pk_j.is_identity() {
                return false;
            }
            out_buf[1 + j] = pk_j.compress().to_bytes();
        }
        true
    }

    pub fn compute_validator_vrf_share(
        epoch_secret_share: &Scalar,
        alpha: &[u8],
        entropy_32: &[u8; 32],
    ) -> ([u8; 32], [u8; 64]) {
        let share_pk = epoch_secret_share * ED25519_BASEPOINT_TABLE;
        let h_pt = hash_to_curve(alpha);
        let gamma_pt = epoch_secret_share * h_pt;
        let proof = prove_dleq(
            epoch_secret_share,
            &ED25519_BASEPOINT_POINT,
            &share_pk,
            &h_pt,
            &gamma_pt,
            alpha,
            entropy_32,
        );
        (gamma_pt.compress().to_bytes(), proof)
    }

    pub fn verify_validator_vrf_share(
        share_pk_bytes: &[u8; 32],
        alpha: &[u8],
        gamma_bytes: &[u8; 32],
        proof_64: &[u8; 64],
    ) -> bool {
        let (Some(share_pk), Some(gamma_pt)) = (
            decode_prime_order_point(share_pk_bytes),
            decode_prime_order_point(gamma_bytes),
        ) else {
            return false;
        };
        let h_pt = hash_to_curve(alpha);
        verify_dleq(
            &ED25519_BASEPOINT_POINT,
            &share_pk,
            &h_pt,
            &gamma_pt,
            alpha,
            proof_64,
        )
    }

    pub(crate) fn lagrange_combine_packed(
        epoch_pk_bytes: &[u8; 32],
        alpha: &[u8],
        packed_36b: &[u8],
        shares_count: usize,
        out_64: &mut [u8; 64],
    ) -> bool {
        if decode_prime_order_point(epoch_pk_bytes).is_none() {
            return false;
        }
        let mut xs = Vec::with_capacity(shares_count);
        let mut pts = Vec::with_capacity(shares_count);
        for chunk in packed_36b[..shares_count * 36].chunks_exact(36) {
            let idx = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if xs.iter().any(|&(prev, _)| prev == idx) {
                return false;
            }
            let mut gb = [0u8; 32];
            gb.copy_from_slice(&chunk[4..36]);
            let Some(pt) = decode_prime_order_point(&gb) else {
                return false;
            };
            xs.push((idx, Scalar::from((idx as u64) + 1)));
            pts.push(pt);
        }
        let mut combined = EdwardsPoint::identity();
        for i in 0..xs.len() {
            let (_, x_i) = xs[i];
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for j in 0..xs.len() {
                if i == j {
                    continue;
                }
                let (_, x_j) = xs[j];
                num *= x_j;
                den *= x_j - x_i;
            }
            if den == Scalar::ZERO {
                return false;
            }
            combined += (num * den.invert()) * pts[i];
        }
        if combined.is_identity() {
            return false;
        }
        let gamma_b = combined.compress().to_bytes();
        let mut pre = Vec::with_capacity(18 + 32 + 8 + alpha.len() + 32);
        pre.extend_from_slice(b"SLX_VM_VRF_OUT_V1:");
        pre.extend_from_slice(epoch_pk_bytes);
        pre.extend_from_slice(&(alpha.len() as u64).to_be_bytes());
        pre.extend_from_slice(alpha);
        pre.extend_from_slice(&gamma_b);
        let rnd = keccak256(&pre);
        out_64[0..32].copy_from_slice(&gamma_b);
        out_64[32..64].copy_from_slice(&rnd);
        true
    }

    pub fn he_encrypt_u64(
        pk_bytes: &[u8; 32],
        value: u64,
        randomness: &Scalar,
    ) -> Option<[u8; 64]> {
        let y_pt = decode_prime_order_point(pk_bytes)?;
        let c1 = randomness * ED25519_BASEPOINT_TABLE;
        let c2 = &Scalar::from(value) * ED25519_BASEPOINT_TABLE + randomness * y_pt;
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(c1.compress().as_bytes());
        out[32..64].copy_from_slice(c2.compress().as_bytes());
        Some(out)
    }

    pub fn he_add_ciphertexts(ca: &[u8; 64], cb: &[u8; 64]) -> Option<[u8; 64]> {
        let mut ca1 = [0u8; 32];
        let mut ca2 = [0u8; 32];
        let mut cb1 = [0u8; 32];
        let mut cb2 = [0u8; 32];
        ca1.copy_from_slice(&ca[0..32]);
        ca2.copy_from_slice(&ca[32..64]);
        cb1.copy_from_slice(&cb[0..32]);
        cb2.copy_from_slice(&cb[32..64]);
        let a1 = decode_torsion_free_or_identity(&ca1)?;
        let a2 = decode_torsion_free_or_identity(&ca2)?;
        let b1 = decode_torsion_free_or_identity(&cb1)?;
        let b2 = decode_torsion_free_or_identity(&cb2)?;
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice((a1 + b1).compress().as_bytes());
        out[32..64].copy_from_slice((a2 + b2).compress().as_bytes());
        Some(out)
    }

    pub fn he_scale_ciphertext(ct: &[u8; 64], weight: u64) -> Option<[u8; 64]> {
        let mut c1_b = [0u8; 32];
        let mut c2_b = [0u8; 32];
        c1_b.copy_from_slice(&ct[0..32]);
        c2_b.copy_from_slice(&ct[32..64]);
        let c1 = decode_torsion_free_or_identity(&c1_b)?;
        let c2 = decode_torsion_free_or_identity(&c2_b)?;
        let w = Scalar::from(weight);
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice((w * c1).compress().as_bytes());
        out[32..64].copy_from_slice((w * c2).compress().as_bytes());
        Some(out)
    }

    fn he_or01_challenge(
        y_pt: &EdwardsPoint,
        c1_pt: &EdwardsPoint,
        c2_pt: &EdwardsPoint,
        a0: &EdwardsPoint,
        b0: &EdwardsPoint,
        a1: &EdwardsPoint,
        b1: &EdwardsPoint,
        aux_ctx: &[u8],
    ) -> Scalar {
        let mut h = Sha512::new();
        h.update(b"SLX_HE_OR01_V1");
        h.update(y_pt.compress().as_bytes());
        h.update(c1_pt.compress().as_bytes());
        h.update(c2_pt.compress().as_bytes());
        h.update(a0.compress().as_bytes());
        h.update(b0.compress().as_bytes());
        h.update(a1.compress().as_bytes());
        h.update(b1.compress().as_bytes());
        h.update((aux_ctx.len() as u64).to_be_bytes());
        h.update(aux_ctx);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    pub fn prove_he_zero_or_one(
        pk_bytes: &[u8; 32],
        bit: u8,
        randomness: &Scalar,
        aux_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<([u8; 64], [u8; 128])> {
        if bit > 1 || *randomness == Scalar::ZERO {
            return None;
        }
        let y_pt = decode_prime_order_point(pk_bytes)?;
        let ct_64 = he_encrypt_u64(pk_bytes, bit as u64, randomness)?;
        let c1_pt = randomness * ED25519_BASEPOINT_TABLE;
        let c2_pt = if bit == 1 {
            ED25519_BASEPOINT_POINT + randomness * y_pt
        } else {
            randomness * y_pt
        };
        let derive_sc = |tag: u8| -> Scalar {
            let mut h = Sha512::new();
            h.update(b"SLX_HE_OR01_NONCE_V1");
            h.update(randomness.as_bytes());
            h.update(&ct_64);
            h.update((aux_ctx.len() as u64).to_be_bytes());
            h.update(aux_ctx);
            h.update(entropy_32);
            h.update([bit, tag]);
            Scalar::from_bytes_mod_order_wide(&h.finalize().into())
        };
        let k = derive_sc(1);
        let sim_c = derive_sc(2);
        let sim_z = derive_sc(3);
        let (c0, z0, c1, z1) = if bit == 0 {
            let a0 = &k * ED25519_BASEPOINT_TABLE;
            let b0 = k * y_pt;
            let m1 = c2_pt - ED25519_BASEPOINT_POINT;
            let a1 = &sim_z * ED25519_BASEPOINT_TABLE - sim_c * c1_pt;
            let b1 = sim_z * y_pt - sim_c * m1;
            let c = he_or01_challenge(&y_pt, &c1_pt, &c2_pt, &a0, &b0, &a1, &b1, aux_ctx);
            let c0 = c - sim_c;
            (c0, k + c0 * randomness, sim_c, sim_z)
        } else {
            let a0 = &sim_z * ED25519_BASEPOINT_TABLE - sim_c * c1_pt;
            let b0 = sim_z * y_pt - sim_c * c2_pt;
            let a1 = &k * ED25519_BASEPOINT_TABLE;
            let b1 = k * y_pt;
            let c = he_or01_challenge(&y_pt, &c1_pt, &c2_pt, &a0, &b0, &a1, &b1, aux_ctx);
            let c1 = c - sim_c;
            (sim_c, sim_z, c1, k + c1 * randomness)
        };
        let mut proof = [0u8; 128];
        proof[0..32].copy_from_slice(c0.as_bytes());
        proof[32..64].copy_from_slice(z0.as_bytes());
        proof[64..96].copy_from_slice(c1.as_bytes());
        proof[96..128].copy_from_slice(z1.as_bytes());
        Some((ct_64, proof))
    }

    /// Generates a 64-byte Chaum-Pedersen DLEQ proof that the homomorphic sum ciphertext
    /// `C_sum = (r_sum * B, 1 * B + r_sum * Y)` encrypts `1` under `pk_bytes` (`log_B(C_sum_1) == log_Y(C_sum_2 - B)`).
    pub fn prove_he_sum_equals_one(
        pk_bytes: &[u8; 32],
        r_sum: &Scalar,
        aux_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<[u8; 64]> {
        if *r_sum == Scalar::ZERO {
            return None;
        }
        let y_pt = decode_prime_order_point(pk_bytes)?;
        let c_sum_1 = r_sum * ED25519_BASEPOINT_TABLE;
        let c_sum_2_minus_b = r_sum * y_pt;
        Some(prove_dleq(
            r_sum,
            &ED25519_BASEPOINT_POINT,
            &c_sum_1,
            &y_pt,
            &c_sum_2_minus_b,
            aux_ctx,
            entropy_32,
        ))
    }

    pub fn verify_he_zero_or_one(
        pk_bytes: &[u8; 32],
        ct_64: &[u8; 64],
        aux_ctx: &[u8],
        proof_128: &[u8; 128],
    ) -> bool {
        let Some(y_pt) = decode_prime_order_point(pk_bytes) else {
            return false;
        };
        let mut c1_b = [0u8; 32];
        let mut c2_b = [0u8; 32];
        c1_b.copy_from_slice(&ct_64[0..32]);
        c2_b.copy_from_slice(&ct_64[32..64]);
        let (Some(c1_pt), Some(c2_pt)) = (
            decode_prime_order_point(&c1_b),
            decode_torsion_free_or_identity(&c2_b),
        ) else {
            return false;
        };
        let read_sc = |off: usize| -> Option<Scalar> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&proof_128[off..off + 32]);
            Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
        };
        let (Some(c0), Some(z0), Some(c1), Some(z1)) =
            (read_sc(0), read_sc(32), read_sc(64), read_sc(96))
        else {
            return false;
        };
        let m1_pt = c2_pt - ED25519_BASEPOINT_POINT;
        let a0 = &z0 * ED25519_BASEPOINT_TABLE - c0 * c1_pt;
        let b0 = z0 * y_pt - c0 * c2_pt;
        let a1 = &z1 * ED25519_BASEPOINT_TABLE - c1 * c1_pt;
        let b1 = z1 * y_pt - c1 * m1_pt;
        (c0 + c1) == he_or01_challenge(&y_pt, &c1_pt, &c2_pt, &a0, &b0, &a1, &b1, aux_ctx)
    }

    pub fn verify_he_ciphertext_pok(
        pk_bytes: &[u8; 32],
        ct_64: &[u8; 64],
        aux_ctx: &[u8],
        proof_96: &[u8; 96],
    ) -> bool {
        let Some(y_pt) = decode_prime_order_point(pk_bytes) else {
            return false;
        };
        let mut c1_b = [0u8; 32];
        let mut c2_b = [0u8; 32];
        c1_b.copy_from_slice(&ct_64[0..32]);
        c2_b.copy_from_slice(&ct_64[32..64]);
        let (Some(c1_pt), Some(c2_pt)) = (
            decode_prime_order_point(&c1_b),
            decode_torsion_free_or_identity(&c2_b),
        ) else {
            return false;
        };
        let read_sc = |off: usize| -> Option<Scalar> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&proof_96[off..off + 32]);
            Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
        };
        let (Some(c), Some(zm), Some(zr)) = (read_sc(0), read_sc(32), read_sc(64)) else {
            return false;
        };
        let r1_pt = &zr * ED25519_BASEPOINT_TABLE - c * c1_pt;
        let r2_pt = &zm * ED25519_BASEPOINT_TABLE + zr * y_pt - c * c2_pt;
        let mut h = Sha512::new();
        h.update(b"SLX_HE_POK_V1");
        h.update(y_pt.compress().as_bytes());
        h.update(c1_pt.compress().as_bytes());
        h.update(c2_pt.compress().as_bytes());
        h.update(r1_pt.compress().as_bytes());
        h.update(r2_pt.compress().as_bytes());
        h.update((aux_ctx.len() as u64).to_be_bytes());
        h.update(aux_ctx);
        c == Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    }

    pub fn compute_validator_decryption_share(
        epoch_secret_share: &Scalar,
        c1_bytes: &[u8; 32],
        dec_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 64])> {
        let c1_pt = decode_torsion_free_or_identity(c1_bytes)?;
        if c1_pt.is_identity() {
            return Some((super::IDENTITY_POINT_BYTES, [0u8; 64]));
        }
        let share_pk = epoch_secret_share * ED25519_BASEPOINT_TABLE;
        let d_pt = epoch_secret_share * c1_pt;
        let proof = prove_dleq(
            epoch_secret_share,
            &ED25519_BASEPOINT_POINT,
            &share_pk,
            &c1_pt,
            &d_pt,
            dec_ctx,
            entropy_32,
        );
        Some((d_pt.compress().to_bytes(), proof))
    }

    pub fn verify_validator_decryption_share(
        share_pk_bytes: &[u8; 32],
        c1_bytes: &[u8; 32],
        d_j_bytes: &[u8; 32],
        dec_ctx: &[u8],
        proof_64: &[u8; 64],
    ) -> bool {
        let Some(share_pk) = decode_prime_order_point(share_pk_bytes) else {
            return false;
        };
        let Some(c1_pt) = decode_torsion_free_or_identity(c1_bytes) else {
            return false;
        };
        if c1_pt.is_identity() {
            return *d_j_bytes == super::IDENTITY_POINT_BYTES && *proof_64 == [0u8; 64];
        }
        let Some(d_pt) = decode_torsion_free_or_identity(d_j_bytes) else {
            return false;
        };
        verify_dleq(
            &ED25519_BASEPOINT_POINT,
            &share_pk,
            &c1_pt,
            &d_pt,
            dec_ctx,
            proof_64,
        )
    }

    pub(crate) fn lagrange_decrypt_packed(
        c1_bytes: &[u8; 32],
        c2_bytes: &[u8; 32],
        packed_36b: &[u8],
        shares_count: usize,
        max_val: u64,
        out_72: &mut [u8; 72],
    ) -> i32 {
        let (Some(c1_pt), Some(c2_pt)) = (
            decode_torsion_free_or_identity(c1_bytes),
            decode_torsion_free_or_identity(c2_bytes),
        ) else {
            return 0;
        };
        let combined_d = if c1_pt.is_identity() {
            EdwardsPoint::identity()
        } else {
            if shares_count == 0 {
                return 0;
            }
            let mut xs = Vec::with_capacity(shares_count);
            let mut pts = Vec::with_capacity(shares_count);
            for chunk in packed_36b[..shares_count * 36].chunks_exact(36) {
                let idx = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if xs.iter().any(|&(prev, _)| prev == idx) {
                    return 0;
                }
                let mut db = [0u8; 32];
                db.copy_from_slice(&chunk[4..36]);
                let Some(pt) = decode_torsion_free_or_identity(&db) else {
                    return 0;
                };
                xs.push((idx, Scalar::from((idx as u64) + 1)));
                pts.push(pt);
            }
            let mut acc = EdwardsPoint::identity();
            for i in 0..xs.len() {
                let (_, x_i) = xs[i];
                let mut num = Scalar::ONE;
                let mut den = Scalar::ONE;
                for j in 0..xs.len() {
                    if i == j {
                        continue;
                    }
                    let (_, x_j) = xs[j];
                    num *= x_j;
                    den *= x_j - x_i;
                }
                if den == Scalar::ZERO {
                    return 0;
                }
                acc += (num * den.invert()) * pts[i];
            }
            acc
        };
        let m_pt = c2_pt - combined_d;
        out_72[0..32].copy_from_slice(combined_d.compress().as_bytes());
        out_72[32..64].copy_from_slice(m_pt.compress().as_bytes());

        // Solve discrete log in `[0, max_val]` via BSGS
        const STEP: u64 = 4096;
        let bound = max_val.min(16_777_216);
        let mut table = std::collections::HashMap::with_capacity(STEP as usize);
        let mut pt = EdwardsPoint::identity();
        for b in 0..(STEP as u32) {
            table.insert(pt.compress().to_bytes(), b);
            pt += ED25519_BASEPOINT_POINT;
        }
        let giant_neg = -(&Scalar::from(STEP) * ED25519_BASEPOINT_TABLE);
        let mut cur = m_pt;
        for q in 0..=(bound / STEP) {
            if let Some(&rem) = table.get(&cur.compress().to_bytes()) {
                let cand = q * STEP + (rem as u64);
                if cand <= bound {
                    out_72[64..72].copy_from_slice(&cand.to_be_bytes());
                    return 1;
                }
            }
            cur += giant_neg;
        }
        2
    }

    /// Deterministically derives a prime-order `Edwards25519` `(secret_scalar, pk_bytes_32)` pair
    /// from `(seed_32, context_bytes)` (matching `@superlexicon/sdk/confidential`).
    pub fn derive_ed25519_keypair(seed_32: &[u8; 32], ctx: &[u8]) -> (Scalar, [u8; 32]) {
        let mut h = Sha512::new();
        h.update(b"SLX_ID_ED25519_V1");
        h.update(seed_32);
        h.update((ctx.len() as u64).to_be_bytes());
        h.update(ctx);
        let mut s = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        if s == Scalar::ZERO {
            s = Scalar::ONE;
        }
        let pk = (&s * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        (s, pk)
    }

    /// Generates a `4,608`-byte 24-bit range proof under `pk_bytes` for `value < 2^24`,
    /// returning `(slot_ct_64, slot_randomness_scalar, packed_4608)`.
    pub fn prove_he_range_u24(
        pk_bytes: &[u8; 32],
        value: u64,
        ctx_prefix: &[u8],
        slot_idx: u32,
        entropy_32: &[u8; 32],
    ) -> Option<([u8; 64], Scalar, Vec<u8>)> {
        if value >= (1u64 << super::CONF_RANGE_BITS) || ctx_prefix.len() > 192 {
            return None;
        }
        let mut packed = vec![0u8; super::CONF_RANGE_PROOF_BYTES];
        let mut r_bits = [Scalar::ZERO; super::CONF_RANGE_BITS];

        for b in 0..super::CONF_RANGE_BITS {
            let bit = ((value >> b) & 1) as u8;
            let mut rh = Sha512::new();
            rh.update(b"SLX_CONF_BIT_RAND_V1:");
            rh.update(ctx_prefix);
            rh.update(slot_idx.to_be_bytes());
            rh.update(entropy_32);
            rh.update([b as u8, bit]);
            let mut rb = Scalar::from_bytes_mod_order_wide(&rh.finalize().into());
            if rb == Scalar::ZERO {
                rb = Scalar::ONE;
            }
            r_bits[b] = rb;

            let mut bit_ctx = Vec::with_capacity(18 + ctx_prefix.len() + 5);
            bit_ctx.extend_from_slice(b"SLX_CONF_BIT01_V1:");
            bit_ctx.extend_from_slice(ctx_prefix);
            bit_ctx.extend_from_slice(&slot_idx.to_be_bytes());
            bit_ctx.push(b as u8);

            let mut bit_ent = *entropy_32;
            bit_ent[0] = bit_ent[0].wrapping_add((b as u8).wrapping_mul(41));
            let (ct_64, proof_128) = prove_he_zero_or_one(pk_bytes, bit, &rb, &bit_ctx, &bit_ent)?;
            let off = b * super::CONF_BIT_PROOF_STRIDE;
            packed[off..off + 64].copy_from_slice(&ct_64);
            packed[off + 64..off + 192].copy_from_slice(&proof_128);
        }

        let mut r_slot = r_bits[super::CONF_RANGE_BITS - 1];
        for b in (0..super::CONF_RANGE_BITS - 1).rev() {
            r_slot = r_slot + r_slot + r_bits[b];
        }
        let slot_ct = he_encrypt_u64(pk_bytes, value, &r_slot)?;
        Some((slot_ct, r_slot, packed))
    }

    /// Generates a 64-byte Chaum-Pedersen DLEQ proof that `C_sum = (r_sum * B, public_amount * B + r_sum * Y)`
    /// encrypts `public_amount` under `pk_bytes`.
    pub fn prove_he_sum_equals_u64(
        pk_bytes: &[u8; 32],
        r_sum: &Scalar,
        sum_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<[u8; 64]> {
        if *r_sum == Scalar::ZERO {
            return Some([0u8; 64]);
        }
        let y_pt = decode_prime_order_point(pk_bytes)?;
        let c1_pt = r_sum * ED25519_BASEPOINT_TABLE;
        let m_diff_pt = r_sum * y_pt;
        Some(prove_dleq(
            r_sum,
            &ED25519_BASEPOINT_POINT,
            &c1_pt,
            &y_pt,
            &m_diff_pt,
            sum_ctx,
            entropy_32,
        ))
    }

    /// Signs `msg_ctx` with `secret` over `base_32` (`pubkey = secret * base_32`).
    pub fn prove_ed25519_schnorr(
        secret: &Scalar,
        base_32: &[u8; 32],
        msg_ctx: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<[u8; 64]> {
        if *secret == Scalar::ZERO {
            return None;
        }
        let base_pt = decode_prime_order_point(base_32)?;
        let pub_pt = secret * base_pt;
        Some(prove_dleq(
            secret,
            &base_pt,
            &pub_pt,
            &base_pt,
            &pub_pt,
            msg_ctx,
            entropy_32,
        ))
    }

    /// Builds stealth counterparty commitment `(h_base_32, p_blind_32)` and `IAS 24` non-insider proof blob
    /// for `(rho, client_pk_32)` against `insider_pks`.
    pub fn prove_stealth_non_insider(
        rho: &Scalar,
        client_pk_32: &[u8; 32],
        insider_pks: &[[u8; 32]],
        ctx_prefix: &[u8],
        entropy_32: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 32], Vec<u8>)> {
        if *rho == Scalar::ZERO {
            return None;
        }
        let client_pt = decode_prime_order_point(client_pk_32)?;
        let h_pt = rho * ED25519_BASEPOINT_TABLE;
        let p_blind_pt = rho * client_pt;
        let h_32 = h_pt.compress().to_bytes();
        let p_blind_32 = p_blind_pt.compress().to_bytes();

        let mut blob = vec![0u8; insider_pks.len() * 96];
        for (j, pk_j) in insider_pks.iter().enumerate() {
            if *pk_j == [0u8; 32] || *pk_j == super::IDENTITY_POINT_BYTES {
                continue;
            }
            let ins_pt = decode_prime_order_point(pk_j)?;
            let q_pt = rho * ins_pt;
            let q_32 = q_pt.compress().to_bytes();
            if q_32 == p_blind_32 {
                return None; // Caller IS an insider!
            }
            let mut ctx = Vec::with_capacity(17 + ctx_prefix.len() + 4);
            ctx.extend_from_slice(b"SLX_IAS24_NEQ_V1:");
            ctx.extend_from_slice(ctx_prefix);
            ctx.extend_from_slice(&(j as u32).to_be_bytes());
            let mut ent_j = *entropy_32;
            ent_j[1] = ent_j[1].wrapping_add(j as u8);
            let dleq = prove_dleq(
                rho,
                &ED25519_BASEPOINT_POINT,
                &h_pt,
                &ins_pt,
                &q_pt,
                &ctx,
                &ent_j,
            );
            let off = j * 96;
            blob[off..off + 32].copy_from_slice(&q_32);
            blob[off + 32..off + 96].copy_from_slice(&dleq);
        }
        Some((h_32, p_blind_32, blob))
    }
}

#[cfg(test)]
mod confidential_tests {
    use super::*;

    #[test]
    fn u24_range_proofs_homomorphic_sum_schnorr_and_ias24_stealth_non_insider() {
        let (_sk_audit, pk_audit) =
            mock_crypto::derive_ed25519_keypair(&[0x11; 32], b"COMPANY_AUDIT_EP1");
        let amounts = [12_500u64, 18_750u64, 0u64, 9_250u64]; // 4 slots including 0-value dummy!
        let expected_total: u64 = amounts.iter().sum();
        let ctx_prefix = b"PAYROLL_BATCH_TEST";

        let mut c_sum = IDENTITY_CIPHERTEXT_64;
        let mut r_sum = mock_crypto::Scalar::ZERO;
        for (idx, &amt) in amounts.iter().enumerate() {
            let mut ent = [0x22u8; 32];
            ent[0] = idx as u8;
            let (slot_ct, r_slot, packed_4608) =
                mock_crypto::prove_he_range_u24(&pk_audit, amt, ctx_prefix, idx as u32, &ent)
                    .expect("valid u24 range proof");
            let verified_ct =
                verify_he_range_u24(&pk_audit, ctx_prefix, idx as u32, &packed_4608)
                    .expect("range proof must verify");
            assert_eq!(slot_ct, verified_ct);

            // Tampering any byte or slot_idx must fail verification
            assert!(verify_he_range_u24(&pk_audit, ctx_prefix, (idx + 1) as u32, &packed_4608).is_none());

            c_sum = he_add_ciphertexts(&c_sum, &verified_ct).unwrap();
            r_sum += r_slot;
        }

        let sum_ctx = b"PAYROLL_SUM_CTX";
        let sum_dleq =
            mock_crypto::prove_he_sum_equals_u64(&pk_audit, &r_sum, sum_ctx, &[0x33; 32]).unwrap();
        assert!(verify_he_sum_equals_u64(
            &pk_audit,
            &c_sum,
            expected_total,
            sum_ctx,
            &sum_dleq
        ));
        // Wrong public sum must be rejected!
        assert!(!verify_he_sum_equals_u64(
            &pk_audit,
            &c_sum,
            expected_total + 1,
            sum_ctx,
            &sum_dleq
        ));

        // Stealth bilateral co-signing + IAS 24 insider non-membership check
        let (_s_dir1, pk_dir1) = mock_crypto::derive_ed25519_keypair(&[0x41; 32], b"DIR1");
        let (_s_cfo, pk_cfo) = mock_crypto::derive_ed25519_keypair(&[0x42; 32], b"CFO");
        let (s_client, pk_client) =
            mock_crypto::derive_ed25519_keypair(&[0x99; 32], b"EXTERNAL_DEFENSE_BUYER");
        let insiders = [pk_dir1, pk_cfo];
        let (rho, _) = mock_crypto::derive_ed25519_keypair(&[0x77; 32], b"STEALTH_RHO");

        let (h_32, p_blind_32, neq_blob) = mock_crypto::prove_stealth_non_insider(
            &rho,
            &pk_client,
            &insiders,
            b"SVC_CONTRACT_0",
            &[0x55; 32],
        )
        .expect("arm's-length client succeeds");
        assert!(verify_stealth_non_insider(
            &h_32,
            &p_blind_32,
            &insiders,
            b"SVC_CONTRACT_0",
            &neq_blob
        ));

        let cosign_sig =
            mock_crypto::prove_ed25519_schnorr(&s_client, &h_32, b"COSIGN_SVC_0", &[0x66; 32])
                .unwrap();
        assert!(verify_ed25519_schnorr(
            &h_32,
            &p_blind_32,
            b"COSIGN_SVC_0",
            &cosign_sig
        ));

        // Insider trying to masquerade as external client MUST fail!
        assert!(mock_crypto::prove_stealth_non_insider(
            &rho,
            &pk_dir1,
            &insiders,
            b"SVC_CONTRACT_0",
            &[0x55; 32],
        )
        .is_none());
    }
}
