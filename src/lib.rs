extern crate rustc_serialize as serialize;
use serialize::hex::FromHex;
use serialize::hex::ToHex;

use std::mem;
use std::collections::HashMap;

pub mod xor;
pub mod constants;
pub use xor::*;


macro_rules! map(
    ( $( $k:expr => $v:expr ),+ ) => {
        {
            let mut map = HashMap::new();
            $(
                map.insert($k,$v);
             )+
                map
        }
    }
);


// estimate keylength in a XOR cipher between *min* and *max*
fn estimate_key_length(cipher :&str,min :usize, max :usize) -> HashMap<usize,f32> {
    let mut results = HashMap::new();
    // for each key size
    for keysize in min..max {
        if keysize*2 < cipher.len() {
            break;
        }
        // take the first two *keysize* blocks
        let b1 = &cipher[..keysize];
        let b2 = &cipher[keysize..keysize*2];
        match hamming_dist(b1,b2) {
            Ok(d) => {
                let normalized = (d as f32) / (keysize as f32);
                results.insert(keysize,normalized);
            },
            Err(_) => continue,
        }
    }
    results
}

// Compute the hamming distance between two strings
fn hamming_dist(s1 :&str, s2 :&str) ->  Result<u32,XorError> {
    if s1.len() != s2.len() {
        return Err(XorError::DifferentSize(s1.len(),s2.len()));
    }
    let mut diff :u32 = 0;
    for (c1,c2) in s1.chars().zip(s2.chars()) {
        let mut b1 = c1 as u8;
        let mut b2 = c2 as u8;
        for _ in 0..7 {
            if (b1 & 1) ^ (b2 & 1) == 1 {
                diff +=1; 
            }
            b1 = b1 >> 1;
            b2 = b2 >> 1;
        }
    }
    Ok(diff)
}

pub trait HexToBytes {
    fn hex_to_bytes(&self) -> Vec<u8>;
}

impl HexToBytes for String {
    fn hex_to_bytes(&self) -> Vec<u8> {
        return self.from_hex().unwrap();
    }
}
pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for String {
    fn to_base64(&self) -> String {
        self.as_bytes().to_base64()
    }
}

impl ToBase64 for [u8] {
    fn to_base64(&self) -> String {
        let end = self.len();
        let mut buf = String::with_capacity(end);
        {
            let mut write = |val| buf.push(val as char);
            let enc = |val| constants::BASE64[val as usize];
            let mut bin = self.iter();//.map(|x| x as u32);
            while let (Some(&n1),Some(&n2),Some(&n3)) = (bin.next(),bin.next(),bin.next()) { 
                let triplet = (n1 as u32) << 16 | (n2 as u32) << 8 | (n3 as u32);

                write(enc((triplet >> 18) & 0x3F));
                write(enc((triplet >> 12) & 0x3F));
                write(enc((triplet >> 6)  & 0x3F));
                write(enc((triplet >> 0)  & 0x3F));
            }

            match self.len() % 3 {
                // means still 2 missing bytes
                1 => {
                    let alone = (self[self.len()-1] as u32) << 16;
                    write(enc((alone >> 18) & 0x3F));
                    write(enc((alone >> 12) & 0x3F));
                    write('=' as u8);
                    write('=' as u8);
                },
                // means 1 missing byte
                2 => {
                    let lasts = (self[self.len()-2] as u32) << 16 | (self[self.len()-1] as u32) << 8;
                    write(enc((lasts >> 18) & 0x3F));
                    write(enc((lasts >> 12) & 0x3F));
                    write(enc((lasts >> 6)  & 0x3F));
                    write('=' as u8);
                }
                0 => (),
                _ => panic!("oh my god"),
            }
        }
        return buf;

    }
}

#[test]
fn test_hamming_dist() {
    let s1 = "this is a test";
    let s2 = "wokka wokka!!!";
    let dist = 37;
    match hamming_dist(s1,s2) {
        Ok(d) => {
            println!("d = {}",d);
            assert!(d == dist);
        },
        _ => assert!(false),
    }
}

#[test]
fn test_map_macro() {
    let m = map!{1=>"1",2=>"2"};
    // get takes a ref of a key and return Option<&V> => ref to the value
    match m.get(&1) {
        Some(&i) if i == "1" => (),
        _ => assert!(false),
    }
}
