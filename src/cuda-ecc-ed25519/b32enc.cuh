#ifndef B32ENC_CUH
#define B32ENC_CUH

#include <stdint.h>

/* RFC 4648 base32 encoding for CUDA.
 *
 * Lowercase alphabet: abcdefghijklmnopqrstuvwxyz234567
 * Pure bit manipulation — no division, no bignums.
 * 5 bits per output character.
 */

/* Extract 5 bits starting at bit position `bit_offset` from a byte array.
 * bit_offset 0 = MSB of byte 0. */
__device__ __host__ static inline int b32_extract5(const uint8_t* data, int bit_offset) {
    int byte_idx = bit_offset >> 3;
    int bit_idx  = bit_offset & 7;

    /* We need 5 bits starting at bit_idx within byte_idx.
     * Combine up to 2 bytes to extract a 5-bit window. */
    int val = (data[byte_idx] << 8);
    val |= data[byte_idx + 1];  /* safe: callers ensure we never read past end */
    val >>= (16 - bit_idx - 5);
    return val & 0x1F;
}

/* Encode exactly 35 bytes -> 56 base32 characters (no padding, no NUL).
 * 35 * 8 = 280 bits, 280 / 5 = 56 characters exactly. */
__device__ __host__ static void base32_enc_full(char out[56], const uint8_t in[35]) {
    static const char b32alpha[] = "abcdefghijklmnopqrstuvwxyz234567";

    /* Append a zero byte so b32_extract5 can safely read one byte past the input
     * when extracting the last 5-bit group. */
    uint8_t buf[36];
    for (int i = 0; i < 35; ++i) buf[i] = in[i];
    buf[35] = 0;

    for (int i = 0; i < 56; ++i) {
        out[i] = b32alpha[b32_extract5(buf, i * 5)];
    }
}

/* Encode the first `out_chars` base32 characters from the beginning of `data`.
 * `data_len` is the number of valid bytes in `data`.
 * Used for fast prefix filtering on the 32-byte public key before computing SHA3. */
__device__ __host__ static void base32_enc_partial(char* out, const uint8_t* data, int data_len, int out_chars) {
    static const char b32alpha[] = "abcdefghijklmnopqrstuvwxyz234567";

    /* Copy into a zero-padded buffer so byte_idx+1 is always safe to read. */
    uint8_t buf[34]; /* max 33 bytes needed + 1 pad */
    int bytes_needed = (out_chars * 5 + 7) / 8 + 1; /* +1 for safe lookahead */
    if (bytes_needed > 34) bytes_needed = 34;
    int copy_len = bytes_needed < data_len ? bytes_needed : data_len;
    for (int i = 0; i < copy_len; ++i) buf[i] = data[i];
    for (int i = copy_len; i < bytes_needed; ++i) buf[i] = 0;

    for (int i = 0; i < out_chars; ++i) {
        int bit_offset = i * 5;
        int byte_idx = bit_offset >> 3;
        int bit_idx  = bit_offset & 7;
        int val = (buf[byte_idx] << 8) | buf[byte_idx + 1];
        val >>= (16 - bit_idx - 5);
        out[i] = b32alpha[val & 0x1F];
    }
}

#endif /* B32ENC_CUH */
