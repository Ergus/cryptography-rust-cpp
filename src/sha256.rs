#![allow(dead_code)]


use std::convert::TryInto;


// SHA-256 constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Right rotation function
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

// SHA-256 logical functions
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

// Padding and preprocessing
fn pad_message(message: &[u8]) -> Vec<u8> {
    let size = message.len();
    let bit_len = (size * 8) as u64;

    let padded_length = ((size + 9 + 63) / 64) * 64;

    let mut pad_message = vec![0u8; padded_length];
    pad_message[..size].copy_from_slice(message);
    pad_message[size] = 0x80;

    for i in 0..8 {
        pad_message[padded_length - 1 - i] = ((bit_len >> (8 * i)) & 0xFF) as u8;
    }

    pad_message
}

// SHA-256 computation
fn sha256_rust(message: &[u8]) -> [u8; 32] {
    let padded_message = pad_message(message);

    let mut h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    for chunk in padded_message.chunks(64) {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }

        for i in 16..64 {
            let sigma0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let sigma1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);

            w[i] = sigma1.wrapping_add(w[i - 7])
                .wrapping_add(sigma0)
                .wrapping_add(w[i - 16]);
        }

        let mut h2 = h;

        for i in 0..64 {
            let sigma0 = rotr(h2[0], 2) ^ rotr(h2[0], 13) ^ rotr(h2[0], 22);
            let sigma1 = rotr(h2[4], 6) ^ rotr(h2[4], 11) ^ rotr(h2[4], 25);

            let t1 = h2[7]
                .wrapping_add(sigma1)
                .wrapping_add(ch(h2[4], h2[5], h2[6]))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let t2 = sigma0.wrapping_add(maj(h2[0], h2[1], h2[2]));

            h2[7] = h2[6];
            h2[6] = h2[5];
            h2[5] = h2[4];
            h2[4] = h2[3].wrapping_add(t1);
            h2[3] = h2[2];
            h2[2] = h2[1];
            h2[1] = h2[0];
            h2[0] = t1.wrapping_add(t2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(h2[i]);
        }
    }

    let mut hash = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        hash[4 * i..4 * i + 4].copy_from_slice(&val.to_be_bytes());
    }

    hash
}

#[cfg(test)]
mod test_sha256 {

    use super::*;

    #[test]
    fn hello_world_rust() {

        let hash = sha256_rust("hello world".as_bytes());

        assert_eq!(hash, [0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d,
            0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7,
            0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84,
            0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9]);
    }
}
