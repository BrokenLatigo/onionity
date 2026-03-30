#!/usr/bin/env python3
"""Verify onion v3 address derivation from ed25519 public key.

Usage:
    python3 verify_onion.py <pubkey_hex>
    python3 verify_onion.py <pubkey_hex> <expected_onion_address>

Examples:
    python3 verify_onion.py d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7e8c...
    python3 verify_onion.py d75a980182b10ab7... abcdefghijk....onion
"""
import hashlib
import base64
import sys


def onion_address_from_pubkey(pubkey_bytes: bytes) -> str:
    """Derive the Tor v3 .onion address from a 32-byte ed25519 public key."""
    assert len(pubkey_bytes) == 32, f"Public key must be 32 bytes, got {len(pubkey_bytes)}"

    version = b'\x03'
    checksum_input = b'.onion checksum' + pubkey_bytes + version
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]

    address_bytes = pubkey_bytes + checksum + version
    # base32 encode, lowercase, no padding
    return base64.b32encode(address_bytes).decode().lower().rstrip('=')


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pubkey_hex> [expected_onion]")
        sys.exit(1)

    pubkey_hex = sys.argv[1]
    pubkey = bytes.fromhex(pubkey_hex)
    addr = onion_address_from_pubkey(pubkey)

    print(f"Public key: {pubkey_hex}")
    print(f"Onion addr: {addr}.onion")
    print(f"Checksum:   {hashlib.sha3_256(b'.onion checksum' + pubkey + b'\x03').hexdigest()[:4]}")

    if len(sys.argv) >= 3:
        expected = sys.argv[2].replace('.onion', '')
        if addr == expected:
            print("VERIFIED: Address matches expected value.")
        else:
            print(f"MISMATCH: Expected {expected}")
            print(f"          Got      {addr}")
            sys.exit(1)


if __name__ == '__main__':
    main()
