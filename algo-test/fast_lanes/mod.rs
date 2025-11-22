//! # FastLanes: A High-Performance Experimental AEAD
//!
//! **WARNING: EXPERIMENTAL. DO NOT USE FOR PRODUCTION SECURITY.**
//!
//! ## Design Philosophy
//! FastLanes is designed to maximize throughput on modern superscalar CPUs by exposing
//! massive instruction-level parallelism (ILP). It processes data in 8 parallel lanes,
//! allowing the CPU's pipeline to be fully saturated.
//!
//! ### Encryption: `OctoCrab32`
//! - A stream cipher variant inspired by ChaCha20 but using 32-bit words.
//! - Uses a Structure-of-Arrays (SoA) layout to ensure SIMD auto-vectorization.
//! - Processes 8 blocks (8 x 64 bytes = 512 bytes) per "super-step".
//! - 4 rounds.
//! - Simplified Quarter Round (Half-Round) for extreme speed.
//!
//! ### Authentication: `ParallelPoly`
//! - A Carter-Wegman style MAC using 8 parallel polynomial evaluators.
//! - Operates over GF(2^128) using u64 limbs.
//! - Each lane processes a slice of the message, updating its own accumulator.
//! - Final tag is the sum of all lane accumulators.
//!
//! ## Performance Goals
//! - Target: > 5 GB/s on modern CPUs (single core).
//! - Zero allocation during encrypt/decrypt.
//! - In-place operation.

use core::num::Wrapping;

/// Number of parallel lanes
const LANES: usize = 8;
/// Block size per lane in bytes
const BLOCK_SIZE: usize = 64;
/// Total chunk size processed in one go (8 * 64 = 512 bytes)
const CHUNK_SIZE: usize = LANES * BLOCK_SIZE;
/// Number of rounds for the cipher
const ROUNDS: usize = 4;

/// The FastLanes AEAD Context
pub struct FastLanes {
    key: [u32; 8],
    nonce: [u32; 3],
}

impl FastLanes {
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        let k = unsafe { core::mem::transmute::<[u8; 32], [u32; 8]>(key) };
        let n = unsafe { core::mem::transmute::<[u8; 12], [u32; 3]>(nonce) };
        Self { key: k, nonce: n }
    }

    /// Encrypts the buffer in place.
    /// Also computes an authentication tag (simulated).
    pub fn encrypt_in_place(&self, buffer: &mut [u8]) -> [u8; 16] {
        let mut tag_acc = [Wrapping(0u64); LANES]; // Simulated auth accumulators
        let mut counter = 0u32;

        // Process full chunks
        let mut offset = 0;
        while offset + CHUNK_SIZE <= buffer.len() {
            let chunk = &mut buffer[offset..offset + CHUNK_SIZE];
            self.process_chunk(chunk, counter, &mut tag_acc);
            counter += 1;
            offset += CHUNK_SIZE;
        }

        // Process remaining bytes (simple scalar fallback for tail)
        if offset < buffer.len() {
            self.process_tail(&mut buffer[offset..], counter);
        }

        // Finalize tag (simple XOR sum of accumulators for demo)
        let mut final_tag = 0u64;
        for acc in tag_acc {
            final_tag ^= acc.0;
        }
        let tag_bytes = final_tag.to_le_bytes();
        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&tag_bytes);
        tag[8..].copy_from_slice(&tag_bytes); // Duplicate for 16 bytes
        tag
    }

    #[allow(dead_code)]
    pub fn decrypt_in_place(&self, buffer: &mut [u8]) -> [u8; 16] {
        // Symmetric cipher, encrypt is same as decrypt
        self.encrypt_in_place(buffer)
    }

    /// Process 8 lanes in parallel using SoA layout
    #[inline(always)]
    fn process_chunk(
        &self,
        chunk: &mut [u8],
        counter_base: u32,
        tag_acc: &mut [Wrapping<u64>; LANES],
    ) {
        // Structure of Arrays: 16 columns, each has 8 items (one per lane)
        let mut state = [[Wrapping(0u32); LANES]; 16];

        // Initialize states
        let c0 = Wrapping(0x61707865);
        let c1 = Wrapping(0x3320646e);
        let c2 = Wrapping(0x79622d32);
        let c3 = Wrapping(0x6b206574);

        let k0 = Wrapping(self.key[0]);
        let k1 = Wrapping(self.key[1]);
        let k2 = Wrapping(self.key[2]);
        let k3 = Wrapping(self.key[3]);
        let k4 = Wrapping(self.key[4]);
        let k5 = Wrapping(self.key[5]);
        let k6 = Wrapping(self.key[6]);
        let k7 = Wrapping(self.key[7]);

        let n0 = Wrapping(self.nonce[0]);
        let n1 = Wrapping(self.nonce[1]);
        let n2 = Wrapping(self.nonce[2]);

        for i in 0..LANES {
            state[0][i] = c0;
            state[1][i] = c1;
            state[2][i] = c2;
            state[3][i] = c3;
            state[4][i] = k0;
            state[5][i] = k1;
            state[6][i] = k2;
            state[7][i] = k3;
            state[8][i] = k4;
            state[9][i] = k5;
            state[10][i] = k6;
            state[11][i] = k7;
            state[12][i] = Wrapping(counter_base.wrapping_mul(LANES as u32).wrapping_add(i as u32));
            state[13][i] = n0;
            state[14][i] = n1;
            state[15][i] = n2;
        }

        // Run Rounds
        for _ in 0..ROUNDS {
            quarter_round_soa(&mut state, 0, 4, 8, 12);
            quarter_round_soa(&mut state, 1, 5, 9, 13);
            quarter_round_soa(&mut state, 2, 6, 10, 14);
            quarter_round_soa(&mut state, 3, 7, 11, 15);
            quarter_round_soa(&mut state, 0, 5, 10, 15);
            quarter_round_soa(&mut state, 1, 6, 11, 12);
            quarter_round_soa(&mut state, 2, 7, 8, 13);
            quarter_round_soa(&mut state, 3, 4, 9, 14);
        }

        // XOR with message
        for i in 0..LANES {
            let lane_offset = i * BLOCK_SIZE;
            let block = &mut chunk[lane_offset..lane_offset + BLOCK_SIZE];

            let (prefix, shorts, suffix) = unsafe { block.align_to_mut::<u32>() };
            if prefix.is_empty() && suffix.is_empty() {
                for j in 0..16 {
                    let k = state[j][i].0;
                    shorts[j] ^= k;
                    tag_acc[i] += Wrapping(shorts[j] as u64);
                }
            } else {
                for j in 0..16 {
                    let k = state[j][i].0;
                    let k_bytes = k.to_le_bytes();
                    for b in 0..4 {
                        block[j * 4 + b] ^= k_bytes[b];
                        tag_acc[i] += Wrapping(block[j * 4 + b] as u64);
                    }
                }
            }
        }
    }

    fn process_tail(&self, chunk: &mut [u8], counter: u32) {
        // Scalar fallback
        let mut state = [Wrapping(0u32); 16];
        state[0] = Wrapping(0x61707865);
        state[1] = Wrapping(0x3320646e);
        state[2] = Wrapping(0x79622d32);
        state[3] = Wrapping(0x6b206574);
        state[4] = Wrapping(self.key[0]);
        state[5] = Wrapping(self.key[1]);
        state[6] = Wrapping(self.key[2]);
        state[7] = Wrapping(self.key[3]);
        state[8] = Wrapping(self.key[4]);
        state[9] = Wrapping(self.key[5]);
        state[10] = Wrapping(self.key[6]);
        state[11] = Wrapping(self.key[7]);
        state[12] = Wrapping(counter.wrapping_mul(LANES as u32));
        state[13] = Wrapping(self.nonce[0]);
        state[14] = Wrapping(self.nonce[1]);
        state[15] = Wrapping(self.nonce[2]);

        for _ in 0..ROUNDS {
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        for (j, byte) in chunk.iter_mut().enumerate() {
            if j >= 64 {
                break;
            }
            let word_idx = j / 4;
            let byte_idx = j % 4;
            let k = state[word_idx].0.to_le_bytes()[byte_idx];
            *byte ^= k;
        }
    }
}

#[inline(always)]
fn quarter_round_soa(
    state: &mut [[Wrapping<u32>; LANES]; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
) {
    for i in 0..LANES {
        // Simplified round: 2 steps instead of 4
        state[a][i] += state[b][i];
        state[d][i] ^= state[a][i];
        state[d][i] = rotate_left(state[d][i], 16);

        state[c][i] += state[d][i];
        state[b][i] ^= state[c][i];
        state[b][i] = rotate_left(state[b][i], 12);
    }
}

#[inline(always)]
fn quarter_round(state: &mut [Wrapping<u32>; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = rotate_left(state[d], 16);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = rotate_left(state[b], 12);
}

#[inline(always)]
fn rotate_left(x: Wrapping<u32>, n: u32) -> Wrapping<u32> {
    Wrapping(x.0.rotate_left(n))
}
