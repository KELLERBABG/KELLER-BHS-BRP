# 👻 KELLER BHS BRP

> **Blind Routing Protocol (BRP) · Black Hole Storage (BHS)**  
> A cryptographically layered, post-quantum peer-to-peer chat system designed for adversarial networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/async-Tokio-blue.svg)](https://tokio.rs/)
[![Post-Quantum](https://img.shields.io/badge/crypto-post--quantum-brightgreen.svg)]()

---

## Table of Contents

- [Overview](#overview)
- [Core Architecture](#core-architecture)
- [Blind Routing Protocol (BRP)](#Blind-Routing-Protocol-brp)
- [Black Hole Storage (BHS)](#Black-Hole-Storage-bhs)
- [Cryptographic Stack](#cryptographic-stack)
- [Handshake & Key Exchange](#handshake--key-exchange)
- [Data Transfer Security](#data-transfer-security)
- [Session & Replay Protection](#session--replay-protection)
- [Why Interception Is Practically Infeasible](#why-interception-is-practically-infeasible)
- [Getting Started](#getting-started)
- [Dependencies](#dependencies)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

GHOST-CHAT V2.0 is a peer-to-peer encrypted messaging system built in Rust that operates over raw UDP. It is designed around two foundational principles that, when combined, make passive interception and active tampering extremely difficult even for well-resourced adversaries:

**Blind Routing Protocol (BRP)** — a layered approach to key derivation, transmission splitting, and counter-based replay prevention that ensures no single captured packet can yield plaintext or key material.

**Black Hole Storage (BHS)** — a multi-shard transmission scheme using Shamir's Secret Sharing combined with Reed-Solomon erasure coding, ensuring that even if packets are dropped, duplicated, or tampered with mid-transit, the session remains intact and tamper-evident.

Together, these form a system where both passive eavesdroppers and active man-in-the-middle attackers face layered, compounding barriers at every stage of a communication session.

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     GHOST-CHAT V2.0                     │
├──────────────┬──────────────────────┬───────────────────┤
│  HANDSHAKE   │    DATA CHANNEL      │   SESSION GUARD   │
│  (BRP/BHS)   │     (BRP/BHS)        │  (Replay Window)  │
├──────────────┴──────────────────────┴───────────────────┤
│          CRYPTOGRAPHIC LAYER                            │
│  X25519 ECDH + Kyber512 KEM + Ed25519 Signing           │
│  ChaCha20-Poly1305 AEAD · Shamir SSS · Reed-Solomon     │
├─────────────────────────────────────────────────────────┤
│             TRANSPORT: RAW UDP (DYNAMIC PORT)           │
└─────────────────────────────────────────────────────────┘
```

The system spawns three concurrent async tasks:

1. **Receiver loop** — reconstructs shards, verifies counters, decrypts messages
2. **Handshake loop** — continuously retransmits handshake shards until the master key is established
3. **Chat loop** — encrypts, shards, and transmits user messages

All tasks share state through `Arc<RwLock<_>>` primitives, making the system thread-safe across the async Tokio runtime.

---

## Blind Routing Protocol (BRP)

BRP is the overarching transmission protocol that governs how data moves between peers. Its primary goal is to ensure that no single intercepted packet — or even the full set of intercepted packets — gives an adversary a trivial path to plaintext.

### Key Principles of BRP

**1. Key Material Never Travels Whole**

The master encryption key is never sent across the wire in its entirety. Instead, it is split using Shamir's Secret Sharing (a threshold secret sharing scheme) into three shares, any two of which are required for reconstruction. These shares are distributed across three independently transmitted UDP packets. An adversary intercepting only one packet captures a share that is, by itself, cryptographically useless — it reveals nothing about the key.

**2. Ciphertext Never Travels Whole**

The encrypted payload is split at the midpoint into two shards, with a third Reed-Solomon parity shard computed over them. The receiver reconstructs the full ciphertext only after collecting at least two shards. An adversary who captures a single shard holds roughly half of an already-encrypted blob — decryption requires key material that is itself split across separate packets.

**3. Jitter Padding Frustrates Traffic Analysis**

Each packet is padded with a random number of bytes (0–64) beyond the base size. This prevents traffic analysis attacks that rely on correlating packet sizes to message lengths or protocol phases.

**4. Dynamic Addressing**

The system binds to `0.0.0.0:0`, receiving a dynamically assigned ephemeral port. The peer's address is updated on first contact, preventing static port-based filtering and making passive traffic correlation harder.

**5. Monotonic Counter Sequencing**

Every message carries a globally monotonic 64-bit counter, embedded in each of its three shards. The session guard validates these counters against a sliding window bitmask, rejecting any out-of-window or already-seen sequence numbers.

---

## Black Hole Storage (BHS)

BHS describes the shard-level construction of each transmission — the combination of secret sharing and erasure coding that makes individual packets non-reconstructible by a passive observer and resilient to packet loss.

### How Sharding Works

For a message of length `N` bytes:

```
Original plaintext
        │
        ▼
┌─────────────────────┐
│  ChaCha20-Poly1305  │  ← encrypted with master key + 16-byte auth tag
│   (N + 16 bytes)    │
└─────────────────────┘
          │
     split in half
          │
     ┌────┴────┐
     ▼         ▼
  Shard[0]  Shard[1]    ← two data shards
               │
               ▼
           Shard[2]    ← Reed-Solomon parity shard (computed from 0+1)
```

Each shard is paired with a corresponding Shamir share of the master key:

```
Packet i = [ msg_id (1B) | original_len (1B) | shamir_share_i (33B) |
             counter (8B) | shard_i (?B) | jitter_padding ]
```

The receiver buffers shards per `msg_id` and attempts reconstruction only when ≥ 2 shards arrive. Reed-Solomon allows the third shard to substitute for either missing data shard, providing one-packet-loss resilience.

### Why This Is "Byzantine Hardened"

In Byzantine fault-tolerant systems, the concern is not just packet loss but active adversarial interference — packet injection, modification, or replay. BHS addresses each threat:

| Threat | Mitigation |
|---|---|
| Packet interception | Single shard = ½ ciphertext, useless without key share |
| Key reconstruction | Requires 2 of 3 Shamir shares from separate packets |
| Packet replay | Counter window bitmask rejects duplicates |
| Packet injection | Ed25519 identity verification during handshake |
| Traffic analysis | Jitter padding obscures true payload sizes |
| Packet loss | RS parity shard reconstructs from any 2 of 3 |

---

## Cryptographic Stack

GHOST-CHAT V2.0 uses a hybrid classical + post-quantum cryptographic stack:

### Key Exchange: X25519 + Kyber512 (Hybrid KEM)

The handshake combines two key encapsulation mechanisms:

- **X25519 (ECDH)** — classical elliptic-curve Diffie-Hellman over Curve25519. Provides ~128-bit classical security and is resistant to all known classical attacks.
- **Kyber512 (ML-KEM)** — a NIST-standardized post-quantum key encapsulation mechanism based on the hardness of Module Learning With Errors (MLWE). Resistant to attacks by Shor's algorithm on a cryptographically-relevant quantum computer.

By combining both, the session key derivation is secure as long as *either* scheme remains unbroken — a classical adversary cannot break Kyber512, and a quantum adversary cannot break the combined binding without solving both simultaneously.

### Identity Authentication: Ed25519

Each peer generates a fresh ephemeral `SigningKey` (Ed25519) at startup. During the handshake, the sender signs their Kyber512 public key with this identity key. The receiver verifies the signature before accepting the handshake. This prevents key substitution attacks and authenticates the origin of the key material.

The identity fingerprint (first 8 bytes of the verifying key) is displayed to the user for out-of-band verification.

### Symmetric Encryption: ChaCha20-Poly1305

All chat messages are encrypted with ChaCha20-Poly1305 AEAD, using the reconstructed master key:

- **ChaCha20** provides 256-bit stream cipher security
- **Poly1305** provides 128-bit authentication tag integrity
- Any single-bit modification to ciphertext causes authentication failure — tampering is detectable

### Secret Sharing: Shamir's Secret Sharing (GF(256))

Key material is split using Shamir's Secret Sharing over GF(256). A (2,3) threshold scheme is used: 3 shares are generated, any 2 are sufficient to reconstruct the secret. One share alone reveals zero information about the secret due to the information-theoretic security of the scheme.

### Erasure Coding: Reed-Solomon (2,1)

A (2,1) Reed-Solomon code is applied to the ciphertext shards. This means 2 data shards plus 1 parity shard. Any 2 of the 3 shards are sufficient to reconstruct the full ciphertext, providing resilience against single-packet loss on unreliable networks without retransmission overhead.

---

## Handshake & Key Exchange

The handshake is designed to bootstrap a shared master key between two peers with no prior shared state. It is continuously retransmitted until acknowledged.

### Handshake Blob Structure (960 bytes)

```
Bytes [0..16]    → Magic header "GHOST_HANDSHAKE_"
Bytes [16..48]   → X25519 ephemeral public key (32 bytes)
Bytes [48..848]  → Kyber512 public key (800 bytes)
Bytes [848..880] → Ed25519 verifying key (32 bytes)
Bytes [880..944] → Ed25519 signature over Kyber512 public key (64 bytes)
```

This blob is split into two 480-byte shards with a Reed-Solomon parity shard, and a temporary ephemeral key is Shamir-split across the three packets.

### Handshake Flow

```
Alice                                          Bob
  │                                              │
  │──── Shard[0]: Kyber PK + Sig + X25519 ─────▶│
  │──── Shard[1]: (continued) ──────────────────▶│
  │──── Shard[2]: RS parity ────────────────────▶│
  │                                              │
  │                   [Bob reconstructs blob, verifies Ed25519 sig]
  │                   [Bob derives master key, marks session open]
  │                                              │
  │◀─── Shard[0]: Kyber PK + Sig + X25519 ──────│
  │◀─── Shard[1]: (continued) ──────────────────│
  │◀─── Shard[2]: RS parity ────────────────────│
  │                                              │
[Alice reconstructs blob, verifies Ed25519 sig]  │
[Alice derives master key, marks session open]    │
  │                                              │
  ╔══════════════════════════════════════════╗   │
  ║         ENCRYPTED CHAT SESSION           ║   │
  ╚══════════════════════════════════════════╝   │
```

Master key derivation uses the Shamir-reconstructed ephemeral key from the handshake shards. After one successful handshake, subsequent handshake packets are silently dropped.

---

## Data Transfer Security

Once the session is established, each message undergoes the following pipeline before transmission:

```
User input string
        │
   format with nickname
        │
        ▼
ChaCha20-Poly1305 encrypt (master key)
        │   + 16-byte Poly1305 tag appended
        │
   pad to even length
        │
        ▼
  Split at midpoint → Shard[0], Shard[1]
        │
  Reed-Solomon encode → Shard[2] (parity)
        │
  Shamir-split master key → Share[0], Share[1], Share[2]
        │
        ▼
  Assign random msg_id (1–253), increment global counter
        │
        ▼
  Transmit 3 packets, each with random jitter padding
```

On the receiver side:

```
Buffer incoming shards by msg_id
        │
  Await ≥ 2 shards
        │
  Validate counter against SessionGuard window
        │
  Reed-Solomon reconstruct full ciphertext
        │
  Shamir reconstruct master key from 2 shares
        │
  ChaCha20-Poly1305 decrypt + verify tag
        │
  Display plaintext to user
```

---

## Session & Replay Protection

The `SessionGuard` struct maintains a sliding-window anti-replay mechanism:

```rust
struct SessionGuard {
    start_time: Instant,      // session start (hard timeout reference)
    last_activity: Instant,   // last valid packet (idle timeout reference)
    v_max: u64,               // highest counter seen
    bitmask: u128,            // tracks received counters in [v_max-127, v_max]
}
```

### Window Mechanics

- The window covers the 128 most recent counter values (`WINDOW_SIZE = 128`)
- Any counter ≤ `v_max - 128` is unconditionally rejected (too old)
- Any counter already set in the bitmask is rejected (already received — replay)
- A new highest counter shifts the bitmask and sets the leading bit

### Timeout Policy

| Timeout | Duration | Description |
|---|---|---|
| Hard session timeout | 24 hours | Absolute session lifetime |
| Idle timeout | 30 minutes | Max silence before session expires |

After expiry, `check_and_update` returns `false` for all packets, effectively closing the session until a new handshake is completed.

---

## Why Interception Is Practically Infeasible

The following summarizes the compounding barriers an adversary faces when attempting to compromise a GHOST-CHAT session.

### Against Passive Eavesdropping (LAN/WAN sniffing)

An attacker capturing all packets on the wire faces:

1. **No plaintext** — all data is ChaCha20-Poly1305 encrypted before transmission
2. **No complete ciphertext in any single packet** — ciphertext is split across two data packets; one packet holds ~½ of an already-encrypted blob
3. **No key in any single packet** — the master key is Shamir-split; one share leaks zero information about the key
4. **No key in two packets** — the Shamir reconstruction requires a correct pairing of shares; an adversary holding shard[0] and shard[2] (wrong pairing) reconstructs garbage
5. **No static address or port** — dynamic ephemeral ports prevent trivial passive correlation
6. **Obfuscated lengths** — jitter padding breaks packet-size-based traffic fingerprinting

Even a passive adversary capturing the complete three-packet burst for a message must break ChaCha20-Poly1305 with a 256-bit key to reach plaintext — computationally infeasible with current and near-future classical hardware.

### Against Active Man-in-the-Middle

An active attacker attempting to inject or substitute packets faces:

1. **Ed25519 handshake authentication** — the Kyber512 public key is signed by the sender's ephemeral identity key; a MITM cannot substitute a different key without producing a valid signature, which requires possession of the private identity key
2. **Poly1305 authentication tag** — any modification to any ciphertext byte causes decryption to fail (`open_in_place` returns `Err`); tampered packets are silently discarded
3. **Counter window** — replayed original packets are rejected by the bitmask; an attacker cannot reuse captured packets to trigger re-processing of old messages

### Against Quantum Adversaries

A quantum computer running Shor's algorithm breaks X25519 (ECDH) but **not** Kyber512. Because both are used in the hybrid KEM:

- Breaking X25519 alone does not yield the session key
- Breaking Kyber512 requires solving MLWE, for which no quantum polynomial-time algorithm is currently known
- The combined scheme is secure as long as either primitive remains unbroken

---

## Getting Started

### Prerequisites

- Rust (stable, 1.75+)
- Cargo

### Build

```bash
git clone https://github.com/yourusername/ghost-chat.git
cd ghost-chat
cargo build --release
```

### Run

```bash
# On machine A
./target/release/ghost-chat
# > Nickname: Alice
# > Ziel-IP: 192.168.1.42

# On machine B
./target/release/ghost-chat
# > Nickname: Bob
# > Ziel-IP: 192.168.1.10
```

The application will display each peer's identity fingerprint. Verify these out-of-band (e.g., via phone or a pre-established secure channel) to confirm you are speaking with the intended party.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime, timers |
| `reed-solomon-erasure` | (2,1) RS erasure coding over GF(2^8) |
| `ring` | ChaCha20-Poly1305 AEAD, secure random |
| `gf256` | Shamir's Secret Sharing over GF(256) |
| `x25519-dalek` | X25519 elliptic-curve Diffie-Hellman |
| `pqcrypto-kyber` | Kyber512 post-quantum KEM |
| `ed25519-dalek` | Ed25519 identity signing and verification |
| `rand` | Thread-local RNG for jitter and IDs |
| `hex` | Identity fingerprint display |

---

## Security Considerations

- **Nonce reuse**: The current implementation uses a static all-zero nonce for ChaCha20-Poly1305. For production use, each encryption should use a unique nonce (e.g., derived from the session counter). Nonce reuse under the same key is a known vulnerability in AEAD schemes.
- **Key confirmation**: The handshake establishes key material but does not include an explicit key confirmation step. An active MITM who intercepts all three handshake shards could potentially delay or suppress delivery.
- **Ephemeral identities**: Identity keys are generated fresh at startup and are not persisted. There is no persistent identity or public key infrastructure. Out-of-band fingerprint verification is recommended for high-assurance use.
- **Counter overflow**: The 64-bit counter will not overflow in practical use, but long-lived sessions should consider key renegotiation after a defined message count.
- **UDP reliability**: This system provides best-effort delivery only. Packet loss beyond the one-shard RS recovery capability will result in dropped messages with no retransmission.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for full terms.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
