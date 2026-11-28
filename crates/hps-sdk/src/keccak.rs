//! Pure `#![no_std]` compile-time (`const fn`) Keccak-256 implementation for Ethereum/Lexicon
//! 4-byte function selectors and 32-byte event topic hashes.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

#[inline(never)]
const fn keccak_f1600(mut st: [u64; 25]) -> [u64; 25] {
    let mut round = 0;
    while round < 24 {
        let mut bc = [0u64; 5];
        let mut i = 0;
        while i < 5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            i += 1;
        }

        i = 0;
        while i < 5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            let mut j = 0;
            while j < 25 {
                st[j + i] ^= t;
                j += 5;
            }
            i += 1;
        }

        let mut t = st[1];
        i = 0;
        while i < 24 {
            let j = PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = tmp;
            i += 1;
        }

        let mut j = 0;
        while j < 25 {
            let mut row = [0u64; 5];
            i = 0;
            while i < 5 {
                row[i] = st[j + i];
                i += 1;
            }
            i = 0;
            while i < 5 {
                st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
                i += 1;
            }
            j += 5;
        }

        st[0] ^= RC[round];
        round += 1;
    }
    st
}

const fn load_u64_le(block: &[u8; 136], offset: usize) -> u64 {
    (block[offset] as u64)
        | ((block[offset + 1] as u64) << 8)
        | ((block[offset + 2] as u64) << 16)
        | ((block[offset + 3] as u64) << 24)
        | ((block[offset + 4] as u64) << 32)
        | ((block[offset + 5] as u64) << 40)
        | ((block[offset + 6] as u64) << 48)
        | ((block[offset + 7] as u64) << 56)
}

/// Compute standard Ethereum Keccak-256 (`0x01` domain separator, rate = 136 bytes) at compile time.
#[inline(never)]
pub const fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let rate = 136usize;
    let mut offset = 0usize;

    while offset + rate <= input.len() {
        let mut block = [0u8; 136];
        let mut b = 0;
        while b < rate {
            block[b] = input[offset + b];
            b += 1;
        }
        let mut lane = 0;
        while lane < 17 {
            state[lane] ^= load_u64_le(&block, lane * 8);
            lane += 1;
        }
        state = keccak_f1600(state);
        offset += rate;
    }

    let mut last = [0u8; 136];
    let rem = input.len() - offset;
    let mut b = 0;
    while b < rem {
        last[b] = input[offset + b];
        b += 1;
    }
    last[rem] ^= 0x01;
    last[rate - 1] ^= 0x80;

    let mut lane = 0;
    while lane < 17 {
        state[lane] ^= load_u64_le(&last, lane * 8);
        lane += 1;
    }
    state = keccak_f1600(state);

    let mut out = [0u8; 32];
    let mut w = 0;
    while w < 4 {
        let bytes = state[w].to_le_bytes();
        let mut k = 0;
        while k < 8 {
            out[w * 8 + k] = bytes[k];
            k += 1;
        }
        w += 1;
    }
    out
}

#[inline(never)]
fn keccak_f1600_mut(st: &mut [u64; 25]) {
    let mut round = 0usize;
    while round < 24 {
        let b0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        let b1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        let b2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        let b3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        let b4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        let t0 = b4 ^ b1.rotate_left(1);
        let t1 = b0 ^ b2.rotate_left(1);
        let t2 = b1 ^ b3.rotate_left(1);
        let t3 = b2 ^ b4.rotate_left(1);
        let t4 = b3 ^ b0.rotate_left(1);

        st[0] ^= t0; st[5] ^= t0; st[10] ^= t0; st[15] ^= t0; st[20] ^= t0;
        st[1] ^= t1; st[6] ^= t1; st[11] ^= t1; st[16] ^= t1; st[21] ^= t1;
        st[2] ^= t2; st[7] ^= t2; st[12] ^= t2; st[17] ^= t2; st[22] ^= t2;
        st[3] ^= t3; st[8] ^= t3; st[13] ^= t3; st[18] ^= t3; st[23] ^= t3;
        st[4] ^= t4; st[9] ^= t4; st[14] ^= t4; st[19] ^= t4; st[24] ^= t4;

        let r1 = st[1].rotate_left(1);
        let r6 = st[6].rotate_left(44);
        let r9 = st[9].rotate_left(20);
        let r22 = st[22].rotate_left(61);
        let r14 = st[14].rotate_left(39);
        let r20 = st[20].rotate_left(18);
        let r2 = st[2].rotate_left(62);
        let r12 = st[12].rotate_left(43);
        let r13 = st[13].rotate_left(25);
        let r19 = st[19].rotate_left(8);
        let r23 = st[23].rotate_left(56);
        let r15 = st[15].rotate_left(41);
        let r4 = st[4].rotate_left(27);
        let r24 = st[24].rotate_left(14);
        let r21 = st[21].rotate_left(2);
        let r8 = st[8].rotate_left(55);
        let r16 = st[16].rotate_left(45);
        let r5 = st[5].rotate_left(36);
        let r3 = st[3].rotate_left(28);
        let r18 = st[18].rotate_left(21);
        let r17 = st[17].rotate_left(15);
        let r11 = st[11].rotate_left(10);
        let r7 = st[7].rotate_left(6);
        let r10 = st[10].rotate_left(3);

        st[10] = r1; st[7] = r10; st[11] = r7; st[17] = r11; st[18] = r17;
        st[3] = r18; st[5] = r3; st[16] = r5; st[8] = r16; st[21] = r8;
        st[24] = r21; st[4] = r24; st[15] = r4; st[23] = r15; st[19] = r23;
        st[13] = r19; st[12] = r13; st[2] = r12; st[20] = r2; st[14] = r20;
        st[22] = r14; st[9] = r22; st[6] = r9; st[1] = r6;

        let (a0, a1, a2, a3, a4) = (st[0], st[1], st[2], st[3], st[4]);
        st[0] = a0 ^ ((!a1) & a2); st[1] = a1 ^ ((!a2) & a3); st[2] = a2 ^ ((!a3) & a4); st[3] = a3 ^ ((!a4) & a0); st[4] = a4 ^ ((!a0) & a1);
        let (a0, a1, a2, a3, a4) = (st[5], st[6], st[7], st[8], st[9]);
        st[5] = a0 ^ ((!a1) & a2); st[6] = a1 ^ ((!a2) & a3); st[7] = a2 ^ ((!a3) & a4); st[8] = a3 ^ ((!a4) & a0); st[9] = a4 ^ ((!a0) & a1);
        let (a0, a1, a2, a3, a4) = (st[10], st[11], st[12], st[13], st[14]);
        st[10] = a0 ^ ((!a1) & a2); st[11] = a1 ^ ((!a2) & a3); st[12] = a2 ^ ((!a3) & a4); st[13] = a3 ^ ((!a4) & a0); st[14] = a4 ^ ((!a0) & a1);
        let (a0, a1, a2, a3, a4) = (st[15], st[16], st[17], st[18], st[19]);
        st[15] = a0 ^ ((!a1) & a2); st[16] = a1 ^ ((!a2) & a3); st[17] = a2 ^ ((!a3) & a4); st[18] = a3 ^ ((!a4) & a0); st[19] = a4 ^ ((!a0) & a1);
        let (a0, a1, a2, a3, a4) = (st[20], st[21], st[22], st[23], st[24]);
        st[20] = a0 ^ ((!a1) & a2); st[21] = a1 ^ ((!a2) & a3); st[22] = a2 ^ ((!a3) & a4); st[23] = a3 ^ ((!a4) & a0); st[24] = a4 ^ ((!a0) & a1);

        st[0] ^= RC[round];
        round += 1;
    }
}

/// Zero-allocation `#![no_std]` streaming Keccak-256 sponge hasher.
pub struct KeccakHasher {
    state: [u64; 25],
    buf: [u8; 136],
    pos: usize,
}

impl KeccakHasher {
    pub const fn new() -> Self {
        Self {
            state: [0u64; 25],
            buf: [0u8; 136],
            pos: 0,
        }
    }

    #[inline(always)]
    fn xor_block_136(st: &mut [u64; 25], blk: &[u8]) {
        unsafe {
            let p = blk.as_ptr() as *const u64;
            st[0] ^= u64::from_le(p.add(0).read_unaligned());
            st[1] ^= u64::from_le(p.add(1).read_unaligned());
            st[2] ^= u64::from_le(p.add(2).read_unaligned());
            st[3] ^= u64::from_le(p.add(3).read_unaligned());
            st[4] ^= u64::from_le(p.add(4).read_unaligned());
            st[5] ^= u64::from_le(p.add(5).read_unaligned());
            st[6] ^= u64::from_le(p.add(6).read_unaligned());
            st[7] ^= u64::from_le(p.add(7).read_unaligned());
            st[8] ^= u64::from_le(p.add(8).read_unaligned());
            st[9] ^= u64::from_le(p.add(9).read_unaligned());
            st[10] ^= u64::from_le(p.add(10).read_unaligned());
            st[11] ^= u64::from_le(p.add(11).read_unaligned());
            st[12] ^= u64::from_le(p.add(12).read_unaligned());
            st[13] ^= u64::from_le(p.add(13).read_unaligned());
            st[14] ^= u64::from_le(p.add(14).read_unaligned());
            st[15] ^= u64::from_le(p.add(15).read_unaligned());
            st[16] ^= u64::from_le(p.add(16).read_unaligned());
        }
    }

    pub fn to_bytes(&self) -> [u8; 344] {
        let mut out = [0u8; 344];
        let mut i = 0usize;
        while i < 25 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
            i += 1;
        }
        out[200..336].copy_from_slice(&self.buf);
        out[336..344].copy_from_slice(&(self.pos as u64).to_le_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8; 344]) -> Self {
        let mut state = [0u64; 25];
        let mut i = 0usize;
        while i < 25 {
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(&raw[i * 8..(i + 1) * 8]);
            state[i] = u64::from_le_bytes(b8);
            i += 1;
        }
        let mut buf = [0u8; 136];
        buf.copy_from_slice(&raw[200..336]);
        let mut p8 = [0u8; 8];
        p8.copy_from_slice(&raw[336..344]);
        let pos = (u64::from_le_bytes(p8) as usize).min(135);
        Self { state, buf, pos }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut idx = 0usize;
        if self.pos > 0 {
            let take = (136 - self.pos).min(data.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            idx += take;
            if self.pos == 136 {
                Self::xor_block_136(&mut self.state, &self.buf);
                keccak_f1600_mut(&mut self.state);
                self.pos = 0;
            }
        }
        while idx + 136 <= data.len() {
            Self::xor_block_136(&mut self.state, &data[idx..idx + 136]);
            keccak_f1600_mut(&mut self.state);
            idx += 136;
        }
        if idx < data.len() {
            let rem = data.len() - idx;
            self.buf[..rem].copy_from_slice(&data[idx..]);
            self.pos = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let mut b = self.pos;
        while b < 136 {
            self.buf[b] = 0;
            b += 1;
        }
        self.buf[self.pos] ^= 0x01;
        self.buf[135] ^= 0x80;
        let mut lane = 0;
        while lane < 17 {
            self.state[lane] ^= load_u64_le(&self.buf, lane * 8);
            lane += 1;
        }
        keccak_f1600_mut(&mut self.state);
        let mut out = [0u8; 32];
        let mut w = 0;
        while w < 4 {
            out[w * 8..(w + 1) * 8].copy_from_slice(&self.state[w].to_le_bytes());
            w += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{event_topic, selector};

    #[test]
    fn matches_known_ethereum_and_lexicon_vectors() {
        assert_eq!(
            selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(
            selector("postMessage(bytes32,bytes)"),
            [0x48, 0x2f, 0x63, 0xb0]
        );
        assert_eq!(
            selector("getMessages(bytes32,uint64)"),
            [0xa8, 0xc9, 0x58, 0x2d]
        );
        let topic = event_topic("MessagePosted(bytes32,uint64,address,bytes)");
        assert_eq!(topic[0..4], [0xb9, 0x3e, 0x3e, 0x01]);
    }
}
