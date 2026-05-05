use std::net::UdpSocket;
use rand::Rng;

pub const BASE_SIZE: usize = 512;
pub const JITTER_MAX: usize = 64;
pub const HANDSHAKE_ID: u8 = 255;

// ---------- Packet field offsets (shared by sender and receiver) ----------
//
// Byte layout of every packet (non-handshake and handshake share the same
// header; only payload size differs):
//
//  [0]        msg_id       (u8)  — HANDSHAKE_ID=255 or random 1-253 for data
//  [1]        original_len (u8)  — plaintext byte count before encryption
//  [2..35]    shamir_share (33B) — one of the three Shamir key shares
//  [35..43]   counter      (u64) — big-endian monotonic sequence number
//  [43..]     shard        (?B)  — data or parity shard of the ciphertext
//  [43+shard_len ..] jitter (?B) — random zero-padding (data packets only)

pub const OFFSET_MSG_ID: usize = 0;
pub const OFFSET_ORIG_LEN: usize = 1;
pub const OFFSET_SHARE_START: usize = 2;
pub const OFFSET_SHARE_END: usize = 35;
pub const OFFSET_COUNTER_START: usize = 35;
pub const OFFSET_COUNTER_END: usize = 43;
pub const OFFSET_SHARD_START: usize = 43;

/// Transmit the three pre-built handshake packets to `target`.
///
/// Each packet carries one Shamir share and one RS shard of the
/// 960-byte handshake blob.
///
/// * `shares`  — three Shamir shares of the ephemeral handshake key
/// * `shards`  — three RS shards (480 B each) of the handshake blob
/// * `socket`  — bound UDP socket
/// * `target`  — peer address string (e.g. "192.168.1.42:9000")
pub fn send_handshake_packets(
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    socket: &UdpSocket,
    target: &str,
) {
    for i in 0..3 {
        let mut p = vec![0u8; BASE_SIZE + 64];
        p[OFFSET_MSG_ID] = HANDSHAKE_ID;
        // original_len field is unused for handshake; left as 0
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&0u64.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + 480].copy_from_slice(&shards[i]);
        let _ = socket.send_to(&p, target);
    }
}

/// Transmit the three data packets for one chat message.
///
/// * `msg_id`       — random packet identifier (1–253)
/// * `original_len` — plaintext byte length (before encryption + padding)
/// * `shares`       — three Shamir shares of the master key
/// * `shards`       — two data shards + one RS parity shard of the ciphertext
/// * `shard_len`    — byte length of each shard
/// * `counter`      — monotonic sequence number for this message
/// * `socket`       — bound UDP socket
/// * `target`       — peer address string
pub fn send_data_packets(
    msg_id: u8,
    original_len: usize,
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    shard_len: usize,
    counter: u64,
    socket: &UdpSocket,
    target: &str,
) {
    for i in 0..3 {
        let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
        let mut p = vec![0u8; BASE_SIZE + jitter];
        p[OFFSET_MSG_ID] = msg_id;
        p[OFFSET_ORIG_LEN] = original_len as u8;
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&counter.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + shard_len].copy_from_slice(&shards[i]);
        let _ = socket.send_to(&p, target);
    }
}

/// Parse the counter field from a raw packet buffer.
pub fn parse_counter(buf: &[u8]) -> u64 {
    let mut c = [0u8; 8];
    c.copy_from_slice(&buf[OFFSET_COUNTER_START..OFFSET_COUNTER_END]);
    u64::from_be_bytes(c)
}

/// Compute the effective shard length for a received packet.
///
/// For handshake packets the shard length is always 480.
/// For data packets it is derived from `original_len` (field at byte 1):
/// `ceil((original_len + 16 + 1) / 2) * 2 / 2`.
pub fn shard_len_for(msg_id: u8, original_len: usize) -> usize {
    if msg_id == HANDSHAKE_ID {
        480
    } else {
        let effective = ((original_len + 16 + 1) / 2) * 2;
        effective / 2
    }
}
