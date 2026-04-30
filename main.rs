use reed_solomon_erasure::galois_8::ReedSolomon;
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use gf256::shamir::shamir;
use std::net::UdpSocket;
use std::{sync::Arc, io::{self, Write}, collections::HashMap};
use rand::Rng;
use tokio::time::{sleep, Duration, Instant};
use tokio::sync::RwLock;

// Krypto-Libraries
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KyberTrait;
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey as EdPublicKey, Signature};

const BASE_SIZE: usize = 512;
const JITTER_MAX: usize = 64;
const HANDSHAKE_ID: u8 = 255;
const WINDOW_SIZE: u64 = 128;
const SESSION_HARD_TIMEOUT: Duration = Duration::from_secs(86400); 
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);  

struct SessionGuard {
    start_time: Instant,
    last_activity: Instant,
    v_max: u64,
    bitmask: u128,
}

impl SessionGuard {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
        }
    }

    fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < SESSION_HARD_TIMEOUT &&
        now.duration_since(self.last_activity) < SESSION_IDLE_TIMEOUT
    }

    fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.is_valid() { return false; }
        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= WINDOW_SIZE { self.bitmask = 1; }
            else { self.bitmask = (self.bitmask << shift) | 1; }
            self.v_max = counter;
            self.last_activity = Instant::now();
            true
        } else {
            if counter <= self.v_max.saturating_sub(WINDOW_SIZE) { return false; }
            let offset = (self.v_max - counter) as u32;
            if (self.bitmask & (1 << offset)) != 0 { return false; }
            self.bitmask |= 1 << offset;
            self.last_activity = Instant::now();
            true
        }
    }
}

#[tokio::main]
async fn main() {
    println!("--- GHOST-CHAT V2.0 (DYNAMIC PORT & IDENTITY) ---");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't find a UDP Port");
    let local_addr = socket.local_addr().unwrap();
    println!("[INFO] Bound to: {}", local_addr);

    print!("Nickname: "); io::stdout().flush().unwrap();
    let mut nickname = String::new(); io::stdin().read_line(&mut nickname).unwrap();
    let nickname = nickname.trim().to_string();

    print!("Ziel-IP: "); io::stdout().flush().unwrap();
    let mut target_ip_raw = String::new(); io::stdin().read_line(&mut target_ip_raw).unwrap();
    let target_ip = target_ip_raw.trim().to_string();

    // If no port is given, 9000 is used by default. IPv6 addresses must be given in full form with brackets, e.g. [2001:db8::1]
    let initial_target = if target_ip.contains(':') { target_ip } else { format!("{}:9000", target_ip) };
    let target_addr = Arc::new(RwLock::new(initial_target));
    
    let target_addr_rx = Arc::clone(&target_addr);
    let target_addr_tx = Arc::clone(&target_addr);
    let target_addr_chat = Arc::clone(&target_addr);

    socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(socket);
    let socket_rx = Arc::clone(&socket);
    let socket_tx = Arc::clone(&socket);

    let master_key: Arc<RwLock<Option<[u8; 32]>>> = Arc::new(RwLock::new(None));
    let master_key_rx = Arc::clone(&master_key);
    let master_key_tx = Arc::clone(&master_key);
    let global_tx_counter = Arc::new(RwLock::new(0u64));

    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);
    let my_identity = SigningKey::from_bytes(&seed);
    println!("[SYSTEM] Your ID Fingerprint: {}", hex::encode(&my_identity.verifying_key().to_bytes()[0..8]));

    // --- RECEIVER THREAD ---
    tokio::spawn(async move {
        let mut pool: HashMap<u8, (Vec<Vec<u8>>, Vec<Vec<u8>>, usize, u64)> = HashMap::new();
        let mut guard = SessionGuard::new();

        loop {
            let mut buf = [0u8; 2048];
            if let Ok((len, from_addr)) = socket_rx.recv_from(&mut buf) {
                let msg_id = buf[0];
                
                if msg_id == HANDSHAKE_ID {
                    let mut t = target_addr_rx.write().await;
                    let new_addr = from_addr.to_string();
                    if *t != new_addr {
                        *t = new_addr;
                        println!("\n[INFO] Target address updated to {}.", from_addr);
                    }
                }

                if msg_id != 0 { 
                    let msg_len = buf[1] as usize;
                    let mut c_bytes = [0u8; 8];
                    c_bytes.copy_from_slice(&buf[35..43]);
                    let packet_counter = u64::from_be_bytes(c_bytes);

                    let effective_len = if msg_id == HANDSHAKE_ID { 960 } else { ((msg_len + 16 + 1) / 2) * 2 };
                    let shard_size = effective_len / 2;

                    if len >= 43 + shard_size {
                        let share = buf[2..35].to_vec();
                        let shard = buf[43..43+shard_size].to_vec();

                        let entry = pool.entry(msg_id).or_insert((Vec::new(), Vec::new(), msg_len, packet_counter));
                        entry.0.push(share);
                        entry.1.push(shard);

                        if entry.0.len() >= 2 {
                            if msg_id != HANDSHAKE_ID && !guard.check_and_update(entry.3) {
                                pool.remove(&msg_id);
                                continue;
                            }

                            let key_recovered = shamir::reconstruct(&entry.0[0..2]);
                            let mut recover = vec![Some(entry.1[0].clone()), Some(entry.1[1].clone()), None];
                            
                            if ReedSolomon::new(2, 1).unwrap().reconstruct(&mut recover).is_ok() {
                                let mut combined = [recover[0].as_ref().unwrap().as_slice(), recover[1].as_ref().unwrap().as_slice()].concat();
                                
                                if msg_id == HANDSHAKE_ID {
                                    if master_key_rx.read().await.is_some() {
                                        pool.remove(&msg_id);
                                        continue;
                                    }

                                    let received_kyber_pk = &combined[48..848];
                                    let received_ed_pk_res = EdPublicKey::from_bytes(combined[848..880].try_into().expect("Key len"));
                                    let received_sig_res = Signature::from_bytes(combined[880..944].try_into().expect("Sig len"));

                                    if let (Ok(peer_pk), sig) = (received_ed_pk_res, received_sig_res) {
                                        if peer_pk.verify(received_kyber_pk, &sig).is_ok() {
                                            let mut mk = master_key_rx.write().await;
                                            if mk.is_none() {
                                                let mut k = [0u8; 32]; k.copy_from_slice(&key_recovered[0..32]);
                                                *mk = Some(k);
                                                guard = SessionGuard::new();
                                                println!("\n[TRUST] Handshake verified! ID: {}", hex::encode(&combined[848..856]));
                                                println!("You can now send messages.\n> ");
                                                io::stdout().flush().unwrap();
                                            }
                                        }
                                    }
                                } else {
                                    combined.truncate(entry.2 + 16);
                                    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key_recovered).unwrap();
                                    let dec_key = LessSafeKey::new(unbound);
                                    if let Ok(dec) = dec_key.open_in_place(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut combined) {
                                        println!("\rPartner: {}\n> ", String::from_utf8_lossy(dec));
                                        io::stdout().flush().unwrap();
                                    }
                                }
                            }
                            pool.remove(&msg_id);
                        }
                    }
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    });

    // --- HANDSHAKE LOOP ---
    let tx_hs = Arc::clone(&socket_tx);
    let addr_hs_lock = Arc::clone(&target_addr_tx);
    let mk_checker = Arc::clone(&master_key);
    
    let (my_k_public, _) = kyber512::keypair();
    let my_x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let my_x_public = XPublicKey::from(&my_x_secret);
    
    let mut hs_blob = vec![0u8; 960];
    hs_blob[0..16].copy_from_slice(b"GHOST_HANDSHAKE_");
    hs_blob[16..48].copy_from_slice(my_x_public.as_bytes());
    hs_blob[48..848].copy_from_slice(my_k_public.as_bytes());
    
    let sig = my_identity.sign(my_k_public.as_bytes());
    hs_blob[848..880].copy_from_slice(&my_identity.verifying_key().to_bytes());
    hs_blob[880..944].copy_from_slice(&sig.to_bytes());

    let rs = ReedSolomon::new(2, 1).unwrap();
    let mut hs_temp_key = [0u8; 32];
    SystemRandom::new().fill(&mut hs_temp_key).unwrap();
    let hs_shares = shamir::generate(&mut hs_temp_key, 3, 2);
    let mut hs_shards = vec![hs_blob[0..480].to_vec(), hs_blob[480..960].to_vec(), vec![0u8; 480]];
    rs.encode(&mut hs_shards).unwrap();

    tokio::spawn(async move {
        loop {
            if mk_checker.read().await.is_some() {
                sleep(Duration::from_secs(10)).await;
                continue; 
            } 

            let target = addr_hs_lock.read().await;
            for i in 0..3 {
                let mut p = vec![0u8; BASE_SIZE + 64];
                p[0] = HANDSHAKE_ID;
                p[2..35].copy_from_slice(&hs_shares[i]);
                p[35..43].copy_from_slice(&0u64.to_be_bytes());
                p[43..43+480].copy_from_slice(&hs_shards[i]);
                let _ = tx_hs.send_to(&p, &*target);
            }
            sleep(Duration::from_millis(1500)).await; 
        }
    });

    // --- CHAT LOOP ---
    loop {
        print!("> "); io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let raw = input.trim();
        if raw.is_empty() { continue; }

        let mk_opt = master_key_tx.read().await;
        if let Some(mk) = *mk_opt {
            let target = target_addr_chat.read().await;
            let msg = format!("{}: {}", nickname, raw);
            let mut data = msg.as_bytes().to_vec();
            let original_len = data.len();
            let enc_key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &mk).unwrap());
            enc_key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut data).unwrap();
            
            if data.len() % 2 != 0 { data.push(0); }
            let mid = data.len() / 2;
            let mut shards = vec![data[0..mid].to_vec(), data[mid..].to_vec(), vec![0u8; mid]];
            ReedSolomon::new(2, 1).unwrap().encode(&mut shards).unwrap();
            
            let id = rand::thread_rng().gen_range(1..254);
            let mk_shares = shamir::generate(&mut mk.clone(), 3, 2);
            let mut c_guard = global_tx_counter.write().await;
            *c_guard += 1;
            let current_c = *c_guard;

            for i in 0..3 {
                let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
                let mut p = vec![0u8; BASE_SIZE + jitter];
                p[0] = id; p[1] = original_len as u8;
                p[2..35].copy_from_slice(&mk_shares[i]);
                p[35..43].copy_from_slice(&current_c.to_be_bytes());
                p[43..43+mid].copy_from_slice(&shards[i]);
                let _ = socket_tx.send_to(&p, &*target);
            }
        }
    }
}
