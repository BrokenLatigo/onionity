#ifndef SHA3_CUH
#define SHA3_CUH

#include <stdint.h>

/* Minimal SHA3-256 (NIST) implementation for CUDA.
 *
 * Specialized for exactly 48-byte input (the Tor v3 checksum computation).
 * SHA3-256 rate = 136 bytes, so 48 bytes fits in a single absorption block.
 * Uses NIST domain separation byte 0x06 (not raw Keccak 0x01).
 */

__device__ __host__ static const uint64_t keccak_rc[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

__device__ __host__ static inline void keccak_f1600(uint64_t st[25]) {
    for (int round = 0; round < 24; ++round) {
        /* Theta */
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                st[y + x] ^= D[x];
        }

        /* Rho + Pi */
        uint64_t tmp = st[1];
        static const int rho_offsets[24] = {
             1, 3, 6,10,15,21,28,36,45,55, 2,14,
            27,41,56, 8,25,43,62,18,39,61,20,44
        };
        static const int pi_lanes[24] = {
            10, 7,11,17,18, 3, 5,16, 8,21,24, 4,
            15,23,19,13,12, 2,20,14,22, 9, 6, 1
        };
        for (int i = 0; i < 24; ++i) {
            uint64_t next = st[pi_lanes[i]];
            st[pi_lanes[i]] = ROTL64(tmp, rho_offsets[i]);
            tmp = next;
        }

        /* Chi */
        for (int y = 0; y < 25; y += 5) {
            uint64_t t[5];
            for (int x = 0; x < 5; ++x)
                t[x] = st[y + x];
            for (int x = 0; x < 5; ++x)
                st[y + x] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5]);
        }

        /* Iota */
        st[0] ^= keccak_rc[round];
    }
}

/* Load a little-endian uint64 from bytes (endian-neutral). */
__device__ __host__ static inline uint64_t load64_le(const uint8_t* p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)
        | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
        | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Store a little-endian uint64 to bytes (endian-neutral). */
__device__ __host__ static inline void store64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/* SHA3-256 specialized for exactly 48 bytes of input.
 *
 * SHA3-256 parameters:
 *   rate     = 1088 bits = 136 bytes = 17 lanes
 *   capacity = 512 bits
 *   output   = 256 bits = 32 bytes
 *   padding  = NIST SHA3: append 0x06, then pad with zeros, then set high bit of last rate byte
 *
 * For 48-byte input (6 full lanes):
 *   - Absorb lanes 0..5 from input bytes
 *   - Lane 6 gets partial: input bytes 48..55 don't exist, so we handle padding here
 *   - Specifically: byte 48 = 0x06 (SHA3 domain sep), bytes 49..134 = 0x00, byte 135 = 0x80
 *   - In lane terms: lane 6 = 0x06 at byte offset 0, lane 16 has 0x80 at byte offset 7
 */
__device__ __host__ static void sha3_256_48(uint8_t out[32], const uint8_t in[48]) {
    uint64_t st[25];
    for (int i = 0; i < 25; ++i) st[i] = 0;

    /* Absorb the 48 input bytes into lanes 0..5 (6 full 8-byte lanes = 48 bytes) */
    for (int i = 0; i < 6; ++i)
        st[i] = load64_le(in + 8 * i);

    /* Padding: SHA3 domain separation byte 0x06 goes right after the message.
     * Message ends at byte 48 which is byte 0 of lane 6. */
    st[6] ^= UINT64_C(0x06);

    /* The last byte of the rate block (byte 135 = byte 7 of lane 16) gets 0x80. */
    st[16] ^= UINT64_C(0x80) << 56;

    /* Permute */
    keccak_f1600(st);

    /* Squeeze: output first 32 bytes (4 lanes) */
    for (int i = 0; i < 4; ++i)
        store64_le(out + 8 * i, st[i]);
}

#undef ROTL64

#endif /* SHA3_CUH */
