#!/usr/bin/env python3
"""Generate Tor hidden service directory from hex key material.

Usage:
    python3 write_tor_keys.py <output_dir> <pubkey_hex> <expanded_secret_hex> <onion_hostname>

Example:
    python3 write_tor_keys.py ./hs_myonion \
        d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7e8c... \
        9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031ca... \
        myonionaddress1234567890abcdefghijklmnopqrstuvwx.onion
"""
import os
import sys
import hashlib
import base64


def onion_address_from_pubkey(pubkey_bytes: bytes) -> str:
    version = b'\x03'
    checksum_input = b'.onion checksum' + pubkey_bytes + version
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]
    address_bytes = pubkey_bytes + checksum + version
    return base64.b32encode(address_bytes).decode().lower().rstrip('=')


def write_tor_keys(output_dir: str, pubkey_hex: str, expanded_secret_hex: str, hostname: str):
    pubkey = bytes.fromhex(pubkey_hex)
    secret = bytes.fromhex(expanded_secret_hex)

    assert len(pubkey) == 32, f"Public key must be 32 bytes, got {len(pubkey)}"
    assert len(secret) == 64, f"Expanded secret must be 64 bytes, got {len(secret)}"

    # Verify the hostname matches the pubkey
    expected_addr = onion_address_from_pubkey(pubkey)
    hostname_clean = hostname.replace('.onion', '')
    if expected_addr != hostname_clean:
        print(f"WARNING: hostname doesn't match pubkey!")
        print(f"  Expected: {expected_addr}.onion")
        print(f"  Got:      {hostname}")

    os.makedirs(output_dir, exist_ok=True)

    # hostname
    with open(os.path.join(output_dir, 'hostname'), 'w') as f:
        if not hostname.endswith('.onion'):
            hostname += '.onion'
        f.write(hostname + '\n')

    # hs_ed25519_public_key: 32-byte header + 32-byte pubkey
    header_pub = b'== ed25519v1-public: type0 ==\x00\x00\x00'
    assert len(header_pub) == 32
    with open(os.path.join(output_dir, 'hs_ed25519_public_key'), 'wb') as f:
        f.write(header_pub + pubkey)

    # hs_ed25519_secret_key: 32-byte header + 64-byte expanded secret
    header_sec = b'== ed25519v1-secret: type0 ==\x00\x00\x00'
    assert len(header_sec) == 32
    with open(os.path.join(output_dir, 'hs_ed25519_secret_key'), 'wb') as f:
        f.write(header_sec + secret)

    # Set permissions (Tor requires 700 for dir, 600 for files)
    os.chmod(output_dir, 0o700)
    for fname in ['hostname', 'hs_ed25519_public_key', 'hs_ed25519_secret_key']:
        os.chmod(os.path.join(output_dir, fname), 0o600)

    print(f"Tor hidden service directory written to: {output_dir}/")
    print(f"  hostname:               {hostname}")
    print(f"  hs_ed25519_public_key:  {len(header_pub) + len(pubkey)} bytes")
    print(f"  hs_ed25519_secret_key:  {len(header_sec) + len(secret)} bytes")


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <output_dir> <pubkey_hex> <expanded_secret_hex> <hostname>")
        sys.exit(1)

    write_tor_keys(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == '__main__':
    main()
