// #![feature(test)]

// #[macro_use]
extern crate bit_vec;
extern crate byteorder;
extern crate clap;
extern crate dirs;
extern crate hex;
extern crate indy_crypto;
extern crate ring;
extern crate sled;

// extern crate test;
use std::str;
use std::time::SystemTime;

use bip39::{Language, Mnemonic};
use bit_vec::BitVec;
use byteorder::{LittleEndian, WriteBytesExt};
use clap::{App, Arg, SubCommand};
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

fn concatenate_merge(
    _key: &[u8],              // the key being merged
    old_value: Option<&[u8]>, // the previous value, if one existed
    merged_bytes: &[u8],      // the new bytes being merged in
) -> Option<Vec<u8>> {
    let mut ret = old_value.map(|ov| ov.to_vec()).unwrap_or_else(|| vec![]);
    ret.extend_from_slice(merged_bytes);
    Some(ret)
}

fn main() {
    let matches = App::new("hashd")
        .author("Hunter T. <cryptoquick@gmail.com>")
        .about("A PoW database")
        .subcommand(SubCommand::with_name("init"))
        .subcommand(SubCommand::with_name("hashrate"))
        .subcommand(
            SubCommand::with_name("set")
                .arg(
                    Arg::with_name("volume")
                        .short("v")
                        .takes_value(true)
                        .required(false),
                )
                .arg(Arg::with_name("message").index(1).required(true))
                .arg(Arg::with_name("tag").index(2).required(true)),
        )
        .subcommand(SubCommand::with_name("get").arg(Arg::with_name("tag").index(1).required(true)))
        .get_matches();

    let mut internal_path = dirs::home_dir().unwrap();
    internal_path.push(".hashd");
    internal_path.push("internal");
    let internal_db = Db::start_default(internal_path).unwrap();

    let index_config = sled::ConfigBuilder::new()
        .temporary(true)
        .merge_operator(concatenate_merge)
        .build();

    let index = sled::Db::start(index_config).unwrap();

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

    match matches.subcommand() {
        ("set", Some(sub_matches)) => {
            let volume = sub_matches.value_of("volume").unwrap_or("0");
            let difficulty = volume.parse::<u8>().unwrap();
            let message = sub_matches.value_of("message").unwrap();
            let tag = sub_matches.value_of("tag").unwrap();

            println!("Message: \"{}\" #{}\nVolume: {}", message, tag, volume);

            match internal_db.get("hot_key").unwrap() {
                Some(key) => {
                    let hot_key = SignKey::from_bytes(&key).unwrap();
                    let signature = Bls::sign(&message.as_bytes(), &hot_key).unwrap();
                    let (result, nonce) = pow(signature.as_bytes(), difficulty as usize, 0);

                    index.merge(tag, message.as_bytes().to_vec()).unwrap();

                    println!(
                        "Posted with hash: {}, and nonce: {}",
                        hex::encode(result),
                        nonce
                    );
                }
                None => println!("Secret key not found. Please run `hashd init` first."),
            }
        }
        ("get", Some(sub_matches)) => {
            let tag = sub_matches.value_of("tag").unwrap();
            let messages = index.get(tag).unwrap();

            for message in messages {
                println!("{}", str::from_utf8(&message).unwrap());
            }
        }
        _ => println!("No command given!"),
    }
}
