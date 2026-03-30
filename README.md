# Onionity

CUDA-accelerated Tor v3 (.onion) vanity address generator. Finds Ed25519 keypairs whose onion address starts with a desired prefix.

Based on [solanity](https://github.com/mcf-rocks/solanity) by mcf-rocks.

## How it works

1. Generates random Ed25519 keypairs on the GPU (thousands of threads in parallel)
2. Derives the Tor v3 onion address: `base32(pubkey || SHA3-256_checksum || 0x03)`
3. Checks if the address starts with your desired prefix
4. On match, writes Tor-compatible hidden service key files

### Performance optimization

The address derivation uses a **fast prefix filter**: since the first 51 base32 characters of an onion address are determined entirely by the public key bytes (before the checksum), we can reject ~99.99% of candidates using only a partial base32 encode — skipping the SHA3-256 checksum computation entirely. SHA3-256 is only computed for the rare candidates that pass the prefix filter.

## Requirements

- NVIDIA GPU with CUDA support
- CUDA Toolkit (nvcc)
- Linux (tested) or compatible OS
- Python 3.6+ (for verification scripts)

## Build

```bash
./configure
make -j$(nproc)
```

`./configure` auto-detects your CUDA toolkit and GPU architectures via `nvidia-smi`, then writes a `config.mk` used by the build. The binary is built at `src/release/onionity`.

Alternatively, `./mk` runs configure automatically if needed, then builds.

### GPU Architecture

To manually target a specific GPU architecture instead of auto-detecting:

```bash
GPU_GENCODE="-gencode arch=compute_86,code=sm_86" make -j$(nproc)
```

## Configuration

Edit `src/config.h` before building:

```c
// Prefixes to search for (lowercase base32: a-z, 2-7, ? = wildcard)
__device__ static char const *prefixes[] = {
    "myprefix",
};

// Host-side mirror (must match prefixes above)
static const char *prefixes_host[] = {
    "myprefix",
};
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `STOP_AFTER_KEYS_FOUND` | 1 | Stop after finding N matches |
| `MAX_ITERATIONS` | 999999999 | Maximum kernel launch iterations |
| `ATTEMPTS_PER_EXECUTION` | 100000 | Keys per thread per kernel launch |
| `SEQUENTIAL_SEED` | 1 | 1=fast sequential increment, 0=random per attempt |

### Prefix length vs time

Base32 has 32 possible characters. Expected attempts to find a prefix of length N:

| Length | Expected attempts | ~Time at 100M/s |
|--------|------------------|-----------------|
| 4 | 1,048,576 | instant |
| 5 | 33,554,432 | <1s |
| 6 | 1,073,741,824 | ~10s |
| 7 | 34,359,738,368 | ~6 min |
| 8 | 1,099,511,627,776 | ~3 hours |
| 9 | 35,184,372,088,832 | ~4 days |
| 10 | 1,125,899,906,842,624 | ~130 days |

## Run

```bash
./run
# or directly:
LD_LIBRARY_PATH=./src/release ./src/release/onionity
```

### Output

On finding a match, Onionity:
1. Prints the onion address, public key, and expanded secret key to stdout
2. Creates a Tor-compatible hidden service directory: `hs_<address>/`
   - `hostname` — the .onion address
   - `hs_ed25519_public_key` — 32-byte header + 32-byte public key
   - `hs_ed25519_secret_key` — 32-byte header + 64-byte expanded secret key

### Using with Tor

Copy the generated directory to your Tor hidden service path:

```bash
cp -r hs_youraddress /var/lib/tor/hidden_service
chown -R debian-tor:debian-tor /var/lib/tor/hidden_service
chmod 700 /var/lib/tor/hidden_service
```

Add to your `torrc`:
```
HiddenServiceDir /var/lib/tor/hidden_service
HiddenServicePort 80 127.0.0.1:8080
```

## Verification

Verify a generated address matches the public key:

```bash
python3 scripts/verify_onion.py <pubkey_hex> [expected_onion_address]
```

Regenerate Tor key files from hex output:

```bash
python3 scripts/write_tor_keys.py <output_dir> <pubkey_hex> <secret_hex> <hostname>
```

## Display

The terminal shows a live-updating stats display:

- Per-GPU hash rates
- Total attempts and running time
- ETA based on prefix length probability
- Per-prefix best match seen so far (closest partial match)
- Progress bar showing position relative to statistical average

## License

See [LICENSE](LICENSE) for the original solanity license.
