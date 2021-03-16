use des::{decrypt, encrypt};
use rayon::prelude::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Instant;
fn main() {
    let now = Instant::now();
    let keys = Key::new();
    let npairs = 28; //actually log(npairs)
    let m: HashMap<u64, u64> = keys
        .into_iter()
        .take(1 << npairs)
        .par_bridge()
        .map(move |k| ((hash(k)), k))
        .collect();

    println!(
        "generated {} pairs in {} seconds",
        m.keys().len(),
        now.elapsed().as_secs()
    );

    let keys = Key::new();
    let mat = keys.into_iter().par_bridge().find_any(|k| {
        let h = (dehash(*k));
        m.contains_key(&h)
    });

    match mat {
        Some(k) => {
            let dh = (dehash(k));
            println!(
                "encryption with {:016x} and decryption with {:016x} produce {:016x}",
                m[&dh], k, dh
            );
        }
        None => println!("No match found"),
    }
}

fn testformat(i: u64) -> u32 {
    u32::from_be_bytes(i.to_be_bytes()[0..4].try_into().unwrap())
}

#[derive(Debug)]
struct Key {
    pub key: u64,
}

impl Key {
    fn new() -> Key {
        Key { key: 0 }
    }
}

impl Iterator for Key {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        self.key = (self.key | 0x0101010101010101) + 1;
        Some(self.key)
    }
}

fn hash(key: u64) -> u64 {
    let plaintext = b"weakhash";

    let deskey = key.to_be_bytes();

    let cipher = encrypt(plaintext, &deskey);
    u64::from_be_bytes(cipher.try_into().expect("wrong length"))
}

fn dehash(key: u64) -> u64 {
    let ciphertext = 0xda99d1ea64144f3eu64;

    let deskey = key.to_be_bytes();

    let cipher = decrypt(&ciphertext.to_be_bytes(), &deskey);
    u64::from_be_bytes(cipher.try_into().expect("wrong length"))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self, BufRead};
    use std::path::Path;
    //#[test]
    fn test_key_gen() {
        fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
        where
            P: AsRef<Path>,
        {
            let file = File::open(filename)?;
            Ok(io::BufReader::new(file).lines())
        }
        let mut keygen = super::Key::new();
        if let Ok(lines) = read_lines("./des_keys.txt") {
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(hex) = line {
                    let good = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap();
                    if let Some(gen_hex) = keygen.next() {
                        println!("{:x} from file, {:x} generated", good, gen_hex);
                        assert_eq!(good, gen_hex)
                    }
                }
            }
        }
    }
    #[test]
    fn test_hash() {
        let mut keygen = super::Key::new();
        keygen.next();

        let ciphered = super::hash(keygen.key);
        let known = 0x64685164220c91ae;
        println!("{:016x}\n{:x} \n{:x}", &keygen.key, ciphered, known);
        assert_eq!(ciphered, known)
    }
    #[test]
    fn test_dehash() {
        let mut keygen = super::Key::new();
        keygen.next();

        let ciphered = super::dehash(keygen.key);
        let known = 0x2b2e9341c0351820;
        println!("{:016x}\n{:x} \n{:x}", &keygen.key, ciphered, known);
        assert_eq!(ciphered, known)
    }
}
