// #![feature(test)]

extern crate bit_vec;
extern crate byteorder;
extern crate clap;
extern crate hex;
extern crate libp2p;
extern crate rand;
extern crate ring;
extern crate secp256k1;
extern crate sled;
extern crate untrusted;

// extern crate test;
use std::time::SystemTime;

use bit_vec::BitVec;
use byteorder::{LittleEndian, WriteBytesExt};
use clap::{App, SubCommand};
use ring::digest::{digest, SHA256};
use secp256k1::rand::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// use test::Bencher;

fn gen_keys() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    secp.generate_keypair(&mut rng)
}

fn pow(signature: &[u8], target_difficulty: usize, old_nonce: u128) -> ([u8; 32], u128) {
    let mut result: [u8; 32] = Default::default();
    let mut nonce = old_nonce;

    loop {
        let mut bs = vec![]; // &[0u8, 16];
        bs.write_u128::<LittleEndian>(nonce).unwrap();
        let data: Vec<u8> = [signature, bs.as_slice()].concat();
        let hash = digest(&SHA256, data.as_slice());
        let mut hash_bits = BitVec::from_bytes(hash.as_ref());
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

    if matches.subcommand_matches("init").is_some() {
        let key_pair = gen_keys();
        println!("{:?}", key_pair);
    }

    if matches.subcommand_matches("hashrate").is_some() {
        // const MESSAGE: &[u8] = b"hello, world";
        // let sig = key_pair.sign(MESSAGE);
        let ones = [255; 64];
        hashrate(&ones, 32);
    }
}
