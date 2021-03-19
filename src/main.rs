use openssl::symm::{Cipher, Crypter, Mode};
//use rayon::prelude::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
//use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crossbeam_channel::{bounded, Sender};

//use rustc_hash::FxHashMap as HashMap;
fn main() {
    let nenc = 15;
    let ndec = 15;
    let npairs = 1 << 20;
    let (sender, receiver) = bounded(100);
    let start = Instant::now();

    for seed in (0..u64::MAX).step_by(u64::MAX as usize / (nenc - 1)) {
        let s = sender.clone();
        thread::spawn(move || chain_hash(KeyType::Enc(seed), s));
    }
    let mut keypairs: HashMap<u32, KeyType> = HashMap::new();
    for kp in receiver.iter().take(npairs) {
        keypairs.insert(testformat(kp.hash), kp.key);
    }
    let finished = Instant::now();
    println!(
        "Generated {} keys in {:?}",
        keypairs.keys().len(),
        finished.duration_since(start)
    );
    let (sender, receiver) = bounded(100);

    for seed in (0..u64::MAX).step_by(u64::MAX as usize / (ndec - 1)) {
        let s = sender.clone();
        thread::spawn(move || chain_hash(KeyType::Dec(seed), s));
    }
    let m = receiver
        .into_iter()
        .find(|k| keypairs.contains_key(&testformat(k.hash)))
        .unwrap();
    let matched = Instant::now();
    println!(
        "Match found in {:?}!\n{} and {} are both {:08x}",
        matched.duration_since(finished),
        m.key,
        keypairs.get(&testformat(m.hash)).unwrap(),
        testformat(m.hash)
    )
}
#[allow(dead_code)]
fn testformat(i: u64) -> u32 {
    u32::from_be_bytes(i.to_be_bytes()[0..4].try_into().unwrap())
}
fn chain_hash(seed: KeyType, s: Sender<Keypair>) {
    let mut keypair = Keypair::new(seed).into_iter();
    while s.send(keypair.next().unwrap()).is_ok() {}
}

#[derive(Debug, Clone, Copy)]
enum KeyType {
    Enc(u64),
    Dec(u64),
}
impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Enc(k) => write!(f, "enc({:016x})", k),
            KeyType::Dec(k) => write!(f, "dec({:016x})", k),
        }
    }
}
#[derive(Debug, Clone, Copy)]
struct Keypair {
    key: KeyType,
    hash: u64,
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key {
            KeyType::Enc(k) => write!(f, "{:016x} hashes to {:016x}", k, self.hash),
            KeyType::Dec(k) => write!(f, "{:016x} dehashes to {:016x}", k, self.hash),
        }
    }
}

impl Keypair {
    pub fn new(seed: KeyType) -> Keypair {
        match seed {
            KeyType::Enc(k) => Keypair {
                key: seed,
                hash: hash(k),
            },
            KeyType::Dec(k) => Keypair {
                key: seed,
                hash: dehash(k),
            },
        }
    }
}

impl Iterator for Keypair {
    type Item = Keypair;

    fn next(&mut self) -> Option<Self::Item> {
        match self.key {
            KeyType::Enc(_) => {
                let h = hash(self.hash);
                self.key = KeyType::Enc(self.hash);
                self.hash = h;
                Some(*self)
            }
            KeyType::Dec(_) => {
                let h = dehash(self.hash);
                self.key = KeyType::Dec(self.hash);
                self.hash = h;
                Some(*self)
            }
        }
    }
}

fn hash(key: u64) -> u64 {
    let plaintext = b"weakhash";

    let deskey = &key.to_be_bytes()[..];
    let mut cr = Crypter::new(Cipher::des_ecb(), Mode::Encrypt, deskey, None).unwrap();
    cr.pad(false);
    let data_len = plaintext.len();
    let blocksize = Cipher::des_ecb().block_size();
    let mut ciphertext = vec![0; data_len + blocksize];
    cr.update(plaintext, &mut ciphertext).unwrap();
    u64::from_be_bytes(ciphertext[0..8].try_into().expect("wrong length"))
}

fn dehash(key: u64) -> u64 {
    let ciphertext = &0xda99d1ea64144f3eu64.to_be_bytes()[..];
    let mut cr = Crypter::new(
        Cipher::des_ecb(),
        Mode::Decrypt,
        &key.to_be_bytes()[..],
        None,
    )
    .unwrap();
    cr.pad(false);
    let data_len = ciphertext.len();
    let blocksize = Cipher::des_ecb().block_size();
    let mut plaintext = vec![0; data_len + blocksize];
    cr.update(ciphertext, &mut plaintext).unwrap();
    u64::from_be_bytes(plaintext[0..8].try_into().expect("wrong length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_key_gen() {
        let e = Keypair::new(KeyType::Enc(0));
        let d = Keypair::new(KeyType::Enc(0));

        if let KeyType::Enc(i) = e.key {
            if let KeyType::Dec(j) = d.key {
                assert_eq!(i, j);
                assert_ne!(e.hash, d.hash)
            }
        }
        let e2 = e.into_iter().next().unwrap();
        let d2 = d.into_iter().next().unwrap();
        println!("{:?}, {:?}", e2, d2);
        if let KeyType::Enc(i) = e2.key {
            if let KeyType::Dec(j) = d2.key {
                assert_ne!(i, j);
                assert_ne!(e.hash, d.hash)
            }
        }
    }
    #[test]
    fn test_hash() {
        let key: u64 = 0x01010102;
        let ciphered = super::hash(key);
        let known = 0x64685164220c91ae;
        println!("{:016x}\n{:x} \n{:x}", key, ciphered, known);
        assert_eq!(ciphered, known)
    }
    #[test]
    fn test_dehash() {
        let key: u64 = 0x01010102;
        let ciphered = super::dehash(key);
        let known = 0x2b2e9341c0351820;
        println!("{:016x}\n{:x} \n{:x}", key, ciphered, known);
        assert_eq!(ciphered, known)
    }
}
