use openssl::symm::{Cipher, Crypter, Mode};
//use rayon::prelude::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crossbeam_channel::{bounded, Sender};

//use rustc_hash::FxHashMap as HashMap;
fn main() {
    let nthreads = 16;
    let npairs = 1 << 26;
    let (sender, receiver) = bounded(100);
    let mut keypairs: HashMap<u64, keytype> = HashMap::new();
    let start = Instant::now();

    for seed in (0..u64::MAX).step_by(u64::MAX as usize / (nthreads - 1)) {
        let s = sender.clone();
        thread::spawn(move || chain_hash(seed, s));
    }
    for keys in receiver.iter().take(npairs) {
        keypairs.insert(keys.hash, keys.key);
    }
    let finished = Instant::now();
    println!(
        "Generated {} keys in {:?}",
        keypairs.keys().len(),
        finished.duration_since(start)
    )
}
#[allow(dead_code)]
fn testformat(i: u64) -> u32 {
    u32::from_be_bytes(i.to_be_bytes()[0..4].try_into().unwrap())
}
fn chain_hash(seed: u64, s: Sender<Keypair>) {
    let mut keypair = Keypair::new_enc(seed).into_iter();
    while s.send(keypair.next().unwrap()).is_ok() {}
}

#[derive(Debug, Clone, Copy)]
enum keytype {
    enc(u64),
    dec(u64),
}
#[derive(Debug, Clone, Copy)]
struct Keypair {
    key: keytype,
    hash: u64,
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key {
            keytype::enc(k) => write!(f, "{:016x} hashes to {:016x}", k, self.hash),
            keytype::dec(k) => write!(f, "{:016x} dehashes to {:016x}", k, self.hash),
        }
    }
}

impl Keypair {
    pub fn new_enc(seed: u64) -> Keypair {
        Keypair {
            key: keytype::enc(seed),
            hash: hash(seed),
        }
    }
    pub fn new_dec(seed: u64) -> Keypair {
        Keypair {
            key: keytype::dec(seed),
            hash: dehash(seed),
        }
    }
}

impl Iterator for Keypair {
    type Item = Keypair;

    fn next(&mut self) -> Option<Self::Item> {
        match self.key {
            keytype::enc(i) => {
                let h = hash(self.hash);
                self.key = keytype::enc(self.hash);
                self.hash = h;
                Some(*self)
            }
            keytype::dec(i) => {
                let h = dehash(self.hash);
                self.key = keytype::dec(self.hash);
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
        let e = Keypair::new_enc(0);
        let d = Keypair::new_dec(0);

        if let keytype::enc(i) = e.key {
            if let keytype::dec(j) = d.key {
                assert_eq!(i, j);
                assert_ne!(e.hash, d.hash)
            }
        }
        let e2 = e.into_iter().next().unwrap();
        let d2 = d.into_iter().next().unwrap();
        println!("{:?}, {:?}", e2, d2);
        if let keytype::enc(i) = e2.key {
            if let keytype::dec(j) = d2.key {
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
