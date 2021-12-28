use rayon::iter::{ParallelIterator, IntoParallelRefIterator};

use sha2::{Sha256, Digest};
use sodiumoxide::crypto::secretbox;
use hex::decode;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key;
use lazy_static::lazy_static;
use indicatif::{ParallelProgressIterator, ProgressBar};
use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

struct SalsaMessage {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    time: u32,
}

lazy_static! {
    static ref JOBS: [SalsaMessage; 5] = [
        SalsaMessage {
            nonce: decode("529206b745354e947640aa54ed0a4b2a56356e7908ab2a43").unwrap(),
            ciphertext: decode("2c3166148770f325dfa57709a4581dd1434e742d30ee667b3f53f224a1270cbae23e9b2b70c27225a84d6b5a294d357c1ee6").unwrap(),
            time: 1615896179,
        },
        SalsaMessage {
            nonce: decode("ce4e2a0088f8df7f87956b239a57f5369227e04d95b76577").unwrap(),
            ciphertext: decode("beefd3a867e1679d9d0a8eea7cbab6ed362b06d06e2813c47731149be2f784de0471bedc66e15cd5f3e009addeca0ebe7ba0").unwrap(),
            time: 1615896187,
        },
        SalsaMessage {
            nonce: decode("1e1d3245fc200db20eb85c4e48aa55c9d21945185ca8e7f6").unwrap(),
            ciphertext: decode("9ff3e08e01be84a65c7161e13e2a5ea31802fe4f47389f82e442b3230ef5ff01b4f394f4d73d74f2428cdc77ea77c86d6941").unwrap(),
            time: 1615896198,
        },
        SalsaMessage {
            nonce: decode("3a2acf6188c7e71ae120281b902efd0bcb314c41b7893d1b").unwrap(),
            ciphertext: decode("0c2c9cec591e5656ab3aecc4f8c1cfa0522d59c00883bdbdc69203e773cf3a6297fa7c702b8e89293e3cff70f5cf3b32287c").unwrap(),
            time: 1615896250,
        },
        SalsaMessage {
            nonce: decode("c08997c1fe9934b5522f6a7658c608fd34053df7b91007c2").unwrap(),
            ciphertext: decode("77dc23be36b9bef292103506557557a63fdcabd7cf91a55cdfec6cb473b85b098408e7115e5c2edeb075640757a5b4b79290").unwrap(),
            time: 1615896210,
        }
    ];
}
fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn compute_job(username: &str) -> &str{
    let max = 10;
    for n1 in 0..2 {
        for n2 in 0..max {
            for n3 in 0..max {
                for n4 in 0..max {
                    for job in JOBS.iter() {
                        let key = format!("{}+{}.{}.{}.{}+{}", username, n1.to_string(), n2.to_string(), n3.to_string(), n4.to_string(), job.time.to_string());
                        //println!("{}",key);
                        let nonce: Nonce = Nonce::from_slice(&job.nonce).unwrap();

                        let mut hasher= Sha256::new();
                        hasher.update(key.as_bytes());
                        let hash_key = hasher.finalize();

                        let byte_key = Key::from_slice(&hash_key);
                        let clean_key: Key;
                        match byte_key {
                            // The Key was valid
                            Some(x) => clean_key = x,
                            // The Key was invalid
                            None    => {println!("Error: Cannot Convert Key");continue},
                        };
                        //println!("here");
                        let decrypt_result = secretbox::open(&job.ciphertext, &nonce, &clean_key);
                        match decrypt_result {
                            Ok(_v) => println!("{}",key),
                            Err(_e) => continue,
                        };
                    }
                }
            }
        }
    }
    return "done";
}

fn main() {
    let out = lines_from_file("./out");
    let pb = ProgressBar::new(out.len() as u64);
    out.par_iter().progress_with(pb).map(|p| {
        compute_job(p);
    }).collect()
}