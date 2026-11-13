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
