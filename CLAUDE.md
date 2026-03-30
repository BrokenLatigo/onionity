# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Onionity is a CUDA-accelerated Tor v3 (.onion) vanity address generator. It finds Ed25519 keypairs whose onion address starts with a desired prefix, running on multi-GPU NVIDIA setups. Forked from solanity (Solana vanity generator), with base58 replaced by Tor v3 address derivation (SHA3-256 checksum + base32 encoding).

## Build Commands

```bash
# Build (requires CUDA toolkit with nvcc in PATH)
export PATH=/usr/local/cuda/bin:$PATH
make -j$(nproc)

# Quick rebuild (cleans artifacts first)
./mk

# Run
./run
# or: LD_LIBRARY_PATH=./src/release ./src/release/onionity

# Target specific GPU architecture
GPU_GENCODE="-gencode arch=compute_86,code=sm_86" make -j$(nproc)

# Clean
make clean
```

Binary is produced at `src/release/onionity`. The shared library `src/release/libcuda-crypt.so` is also built and must be in `LD_LIBRARY_PATH`.

## Architecture

### Single translation unit compilation

`vanity.cu` is the entry point and `#include`s other `.cu` files directly (not linked separately):
```
vanity.cu → includes keypair.cu, sc.cu, fe.cu, ge.cu, sha512.cu, sha3.cuh, b32enc.cuh, config.h
```

This means all device code lives in one compilation unit. The `.cuh` files contain `__device__ __host__` inline functions. Do not add separate `.o` targets for these files.

### Kernel data flow

```
seed[32] → SHA-512 → clamp → ge_scalarmult_base → pubkey[32]
  → fast_prefix_check (partial base32 of pubkey only, skips SHA3 for ~99.99% of candidates)
  → SHA3-256(".onion checksum" || pubkey || 0x03)[:2] → checksum
  → base32(pubkey || checksum || 0x03) → 56-char onion address
  → full prefix match → output via match queue
```

### Host ↔ Device communication

- **Match results**: Device writes to `dev_match_queue[]` (ring buffer of `match_record` structs). Host drains after `cudaDeviceSynchronize()` via `cudaMemcpyFromSymbol`.
- **Best-match tracking**: Per-prefix `dev_best_match_len[]` and `dev_best_match_addr[][]` updated with `atomicCAS` in kernel, read by host for stats display.
- **Counters**: `dev_keys_found` and `dev_exec_count` are per-GPU `int*` allocated once in setup, `cudaMemset` to zero each iteration.

### Multi-GPU

GPUs are enumerated with `cudaGetDeviceCount()`. Each GPU gets independent cuRAND states and kernel launches. Synchronization is per-GPU (`cudaSetDevice(g); cudaDeviceSynchronize()`).

## Configuration

Edit `src/config.h` before building. Both `prefixes[]` (`__device__`) and `prefixes_host[]` (host-side) must be kept in sync manually.

Valid prefix characters: `a-z`, `2-7` (base32 alphabet), `?` (wildcard).

`SEQUENTIAL_SEED=1` increments seed as counter (fast, insecure). `SEQUENTIAL_SEED=0` uses `curand()` per attempt.

## Verification

```bash
# Verify an onion address derivation
python3 scripts/verify_onion.py <pubkey_hex> [expected_onion]

# Generate Tor hidden service directory from hex keys
python3 scripts/write_tor_keys.py <dir> <pubkey_hex> <secret_hex> <hostname>
```

## Tor v3 Address Format

- Checksum: `SHA3-256(".onion checksum" || pubkey || 0x03)[:2]` — uses NIST SHA3 (0x06 padding, not raw Keccak 0x01)
- Address: `base32(pubkey[32] || checksum[2] || version[1])` = 56 lowercase chars
- Key files use tagged headers: `"== ed25519v1-public: type0 =="` + 3 NUL bytes (32 bytes total), then raw key bytes
- Secret key file stores 64-byte expanded secret (SHA-512 of seed, clamped), not the 32-byte seed

## Key Constraints

- The Ed25519 math files (`fe.cu`, `ge.cu`, `sc.cu`, `sha512.cu`, `keypair.cu`) are upstream and should not be modified.
- SHA-512 is inlined in the kernel for performance (eliminates branching for the fixed 32-byte input case). Changes to the SHA-512 flow must be inlined the same way.
- `base32_enc_partial` requires a zero-padded buffer to avoid OOB reads near byte boundaries. Always pass `data_len` parameter.
- Device globals (`dev_best_match_len`, `dev_match_queue`, etc.) are defined in `vanity.cu`, not in `config.h`, to avoid multiple-definition issues.
