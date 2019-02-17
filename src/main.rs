// #![feature(test)]

// #[macro_use]
extern crate bincode;
extern crate bit_vec;
extern crate byteorder;
extern crate clap;
extern crate dirs;
extern crate hex;
extern crate indy_crypto;
extern crate libp2p;
extern crate rand;
extern crate ring;
extern crate secp256k1;
extern crate serde_derive;
extern crate sled;

// extern crate test;
use std::time::SystemTime;

use bip39::{Language, Mnemonic};
use bit_vec::BitVec;
use byteorder::{LittleEndian, WriteBytesExt};
use clap::{App, SubCommand};
use indy_crypto::bls::{Bls, SignKey};
use ring::digest::{digest, SHA256};
use sled::Db;

// use test::Bencher;

fn gen_keys() -> (SignKey, SignKey) {
    let sign_key1 = SignKey::new(None).unwrap();
    let sign_key2 = SignKey::new(None).unwrap();
    (sign_key1, sign_key2)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let hash = digest(&SHA256, data);
    hash.as_ref().to_owned()
}

fn pow(signature: &[u8], target_difficulty: usize, old_nonce: u128) -> ([u8; 32], u128) {
    let mut result: [u8; 32] = Default::default();
    let mut nonce = old_nonce;

    loop {
        let mut bs = vec![]; // &[0u8, 16];
        bs.write_u128::<LittleEndian>(nonce).unwrap();
        let data: Vec<u8> = [signature, bs.as_slice()].concat();
        let hash = sha256(&data);
        let mut hash_bits = BitVec::from_bytes(hash.as_slice());
        hash_bits.truncate(target_difficulty);

        if hash_bits.none() {
            result.copy_from_slice(hash.to_owned().as_ref());
            return (result, nonce);
        } else {
            nonce += 1;
        }
    }
}

fn hashrate(signature: &[u8], target_difficulty: u8) {
    let now = SystemTime::now();
    let mut nonce: u128 = 0;

    for i in 0..=target_difficulty {
        println!("Difficulty: {}", i);
        let (result, old_nonce) = pow(signature, i as usize, nonce);
        nonce = old_nonce;
        println!("Result: {}", hex::encode(result));
        println!("Elapsed: {:?}", now.elapsed().unwrap());
        println!("Nonce: {}", nonce);
    }
}

fn main() {
    let matches = App::new("hashd")
        .author("Hunter T. <cryptoquick@gmail.com>")
        .about("A PoW database")
        .subcommand(SubCommand::with_name("init"))
        .subcommand(SubCommand::with_name("hashrate"))
        .get_matches();

    let mut internal_path = dirs::home_dir().unwrap();
    internal_path.push(".hashd");
    internal_path.push("internal");
    let internal_db = Db::start_default(internal_path).unwrap();

    if matches.subcommand_matches("init").is_some() {
        let (sign_key1, sign_key2) = gen_keys();
        internal_db
            .set("hot_key", sign_key1.as_bytes().to_vec())
            .unwrap();
        internal_db
            .set("cold_key", sign_key2.as_bytes().to_vec())
            .unwrap();
        let mnemonic = Mnemonic::from_entropy(sign_key2.as_bytes(), Language::English).unwrap();
        let phrase: &str = mnemonic.phrase();
        println!("Your cold key phrase: {}", phrase);
    }

    if matches.subcommand_matches("hashrate").is_some() {
        const MESSAGE: &[u8] = b"hello, world";
        match internal_db.get("hot_key").unwrap() {
            Some(key) => {
                println!("{:?}", key);
                let hot_key = SignKey::from_bytes(&key).unwrap();
                let signature = Bls::sign(&MESSAGE, &hot_key).unwrap();
                hashrate(signature.as_bytes(), 32);
            }
            None => println!("Secret key not found. Please run `hashd init` first."),
        }
    }
}
