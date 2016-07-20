extern crate rustc_serialize as serialize;
extern crate crypto;

// need to append self because namespace starts from the parent module
// see https://github.com/rust-lang/rust/issues/17056
use self::serialize::hex::FromHex;
use self::serialize::hex::ToHex;

use self::crypto::aes;
use self::crypto::blockmodes;
use self::crypto::symmetriccipher::Decryptor;
use self::crypto::buffer;
use self::crypto::buffer::{BufferResult,WriteBuffer,ReadBuffer};

use std::mem;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ops::Range;

use xor::*;
use constants;

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

pub fn is_aes_ecb(cipher :&[u8]) -> bool {
    // split in 16 blocks
    for (i,block) in cipher.chunks(16).enumerate() {
        // compare with other 16 blocks
        for (j,block2) in cipher.chunks(16).enumerate() {
            if i == j {
                continue
            }
            if block == block2 {
                println!("Block {} and {} are equal!",i,j);
                return true;
            }
        }
    }

    false
}
pub fn decrypt_aes_cbc(msg :&[u8],key :&[u8]) -> Vec<u8> {
    let mut dec = aes::ecb_decryptor(aes::KeySize::KeySize128,key,blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(msg);
    let mut buff = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buff);

    loop {
        let result = dec.decrypt(&mut read_buffer, &mut write_buffer, true);
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow)=> { panic!("yo"); }
            Err(e) => panic!(e),
        }
    }
    return final_result;
}


pub fn break_repeating_xor(cipher :&[u8]) -> Option<(String,Vec<u8>)> {
    // get key length possibilities
    let klens = estimate_key_length(cipher,5,40);
    println!("Key Length estimate : {:?}",klens.clone());
    //let mut best_score = -1.0;
    //let mut best_key :Vec<u8> = Vec::new();
    let ntries = 20;
    let mut tries :Vec<(f64,Vec<u8>)>= Vec::with_capacity(ntries);
    // lets take the highest probable ones
    for (siz,score) in klens.into_iter().take(ntries) {
        //if siz != 29 {
        //continue
        //}
        // store the key decryption
        let mut key :Vec<u8> = Vec::with_capacity(siz);
        // lets transpose & split up the ciphertext to get each bytes of the key
        for i in 0..siz {
            let block :Vec<u8> = cipher.iter().enumerate().filter(|&(j,c)| (j % siz) == i).map(|(j,c)| *c).collect();
            let best_key = frequency_analysis_simple(&block,(32..127),constants::FREQUENCY);
            //let mut plain :Vec<u8> = cipher.iter().map(|x| x ^ best_key).collect();
            key.push(best_key as u8);
        } 

        // decrypt the whole message now
        let decrypted = xor_repeat(cipher,&key);
        // compute the chisquare of that
        let score = chi_square_pearson(&decrypted,constants::FREQUENCY);        
        println!("Key length {}\tscore {}\t\t{}",siz,score,String::from_utf8(key.clone()).unwrap());
        tries.push((score,key));
    }

    tries.sort_by( |a,b|  a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    let tuple = tries.first().unwrap();
    println!("Best: score {}\t\t{:?}",tuple.0,String::from_utf8(tuple.1.clone()).unwrap());
    let best_plain = xor_repeat(cipher,&tuple.1);
    match String::from_utf8(best_plain) {
        Ok(plaint) => Some((plaint,tuple.1.clone())),
        Err(e) => { println!("Error decrypting: {:?}",e); None},
    }
}

// decrypt a cipher text that has been encrypted using a single byte key
// return the plaintext and key
pub fn decrypt_single_xor(cipher :&[u8],language :&[f64],kguesses :Range<u8>) -> (String,char) {
    // try each letter of the ASCII Uppercase
    //let mut key_guess = 65u8..91;
    let best_key = frequency_analysis_pearson(cipher,kguesses,language);
    //let best_key = frequency_analysis_ic(cipher,key_guess);
    // TODO refactor function signature to return a Result with plaintext + key stored inside
    let mut plaintext :Vec<u8> = cipher.iter().map(|x| x ^ best_key).collect();
    let re = String::from_utf8(plaintext).unwrap();
    return (re,best_key as char)
}
// run the analysis against etaoin shRDLU
fn frequency_analysis_simple(cipher :&[u8],guesses :Range<u8>,language :&[f64]) -> u8 {
    let mut min :f64 = 0.0;
    let mut kc :u8 = 0;
    for k in guesses {
        let decrypt :Vec<u8> = cipher.iter().map( |x| x ^ k).collect();
        let mut freqs = decrypt.iter().fold(HashMap::<char,f64>::new(),
        |mut acc,&ch| {
            match (ch as char).to_lowercase().next() {
                Some(c) if (ch as char).is_alphabetic() => { 
                    *acc.entry(ch as char).or_insert(0.0) += 1.0;
                    acc
                },
                _ => acc
            }
        });
        // take the first 12
        let mut sorted = freqs.iter().fold(Vec::<(char,f64)>::new(),|mut acc, (&ch,&fr)| {
            acc.push((ch,fr));
            acc
        });
        sorted.sort_by( |a,b|  b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let tops_text= sorted.iter().take(constants::TOP12_ENG.len()).fold(HashMap::<char,f64>::new(), |mut acc,&(ch,fr)| {
            acc.insert(ch,fr);
            acc
        });
        // check if it looks like ETAOINSHRDLU
        let top12 = constants::TOP12_ENG.chars().zip(constants::TOP12_ENG_FREQ).fold(HashMap::<char,f64>::new(),|mut acc,(ch,&fr)| { 
            acc.insert(ch,fr);
            acc
        });

        // do a pearson on the top 12
        let score = top12.iter().fold(0.0, |acc, (ch_lang,freq_lang)| {
            // get the freq of the text normalized 
            let freq_txt = match tops_text.get(ch_lang) {
                Some(f) => f / (cipher.len() as f64),
                _ => 0.0,
            };
            // normalize the freqs of the language
            let freq_lang_norm :f64 = freq_lang / 100.0;
            // chisquare
            let diff = (freq_txt - freq_lang_norm).powi(2) / freq_lang_norm;
            // correlation
            //let diff =  freq_txt * freq_lang_norm;
            acc + diff
        });

        match String::from_utf8(decrypt) {
            Ok(d) => {
                if min > score || min == 0.0 {
                    min = score;
                    kc = k;
                }
            },
            _ => continue,
        };
    }
    return kc;
}


// run the pearson correlation for a range of keys and return the best one
fn frequency_analysis_pearson(cipher :&[u8],guesses :Range<u8>,language :&[f64]) -> u8 {
    let mut min :f64 = 0.0;
    let mut kc :u8 = 0;
    for k in guesses {
        let decrypt :Vec<u8> = cipher.iter().map( |x| x ^ k).collect();
        let chi = chi_square_pearson(&decrypt,language);
        match String::from_utf8(decrypt) {
            Ok(d) => {
                //println!("Pearson analysis: key {}, chi {},\t{}",k as char,chi,d);
                if min > chi || min == 0.0 {
                    min = chi;
                    kc = k;
                }
            },
            _ => continue,
        };
    }
    return kc;
}

fn chi_square_pearson(text :&[u8], language:&[f64]) -> f64 {
    // determine frequency
    let mut freqs = text.iter().fold(HashMap::<u8,f64>::new(),
    |mut acc,&ch| {
        match (ch as char).to_lowercase().next() {
            Some(c) if (ch as char).is_alphabetic() => { 
                *acc.entry((c as u8)-97).or_insert(0.0) += 1.0;
                acc
            },
            _ => acc
        }
    });

    //    let chi = freqs.iter().fold(0.0,|acc,(idx_letter,nb_letter)| {
    //let freq_letter = nb_letter / text.len() as f64;
    //let freq_lang = language[*idx_letter as usize] / 100.0;
    //let diff = (freq_letter - freq_lang).powi(2) / freq_lang;
    //acc + diff
    //});
    //chisquare test with english frequency
    let chi = language.iter().enumerate().fold(0.0,|acc,(idx,freq_lang)| { 
        // get the freq of the text normalized 
        let freq_txt = match freqs.get(&(idx as u8)) {
            Some(f) => f / (text.len() as f64),
            _ => 0.0,
        };
        // normalize the freqs of the language
        let freq_lang_norm :f64 = freq_lang / 100.0;
        // chisquare
        let diff = (freq_txt - freq_lang_norm).powi(2) / freq_lang_norm;
        // correlation
        //let diff =  freq_txt * freq_lang_norm;
        acc + diff
    });
    //    //println!("Pearson() Chi={}\tFreqs {:?} ",chi,freqs);
    return chi;
}

// Use of Index Of Coincidence 
fn frequency_analysis_ic(cipher :&[u8],guesses :Range<u8>) -> u8 {
    let mut best :f64 = 0.0;
    let mut kc :u8 = 0;

    for k in guesses {
        let decrypt :Vec<u8> = cipher.iter().map( |x| x ^ k).collect();
        let ic = index_coincidence(&decrypt);
        let diff = (ic - constants::IC_ENG).abs();
        match String::from_utf8(decrypt.clone()) {
            Ok(d) => {
                println!("IC analysis: key {}, ic {},\t{}",k as char,ic,d);
                if diff < best || best == 0.0 {
                    best = diff;
                    kc = k;
                }        
            },
            _ => continue,
        }
    }
    println!("Best IC key : {}",kc as char);
    return kc;
}

fn index_coincidence(text :&[u8]) -> f64 {
    let mut freqs = text.iter().fold(HashMap::<u8,f64>::new(),
    |mut acc,&ch| {
        if (ch > 64  && ch < 91) {
            *acc.entry(ch-65).or_insert(0.0) += 1.0;
        } else if (ch > 96 && ch < 123) {
            *acc.entry(ch-97).or_insert(0.0) += 1.0;
        }
        acc
    });

    let nominator = freqs.iter().fold(0.0,|acc,(byte,freq)| acc + freq * (freq-1.0));
    let ic = nominator / (text.len() * (text.len()-1)) as f64;
    return ic;
}



// estimate keylength in a XOR cipher between *min* and *max*
// returns a map of score for each keysize between min and max
fn estimate_key_length(cipher :&[u8], min :usize, max :usize) -> Vec<(usize,f64)> {
    let mut results = Vec::with_capacity(max - min + 1);
    // for each key size
    for keysize in min..max {
        if keysize*4 > cipher.len() {
            break;
        }
        // take the first two *keysize* blocks
        let b1 = &cipher[..keysize];
        let b2 = &cipher[keysize..keysize*2];
        let b3 = &cipher[keysize*2..keysize*3];
        let b4 = &cipher[keysize*3..keysize*4];
        assert!(b1.len() == b2.len());
        assert!(b1.len() == b3.len());
        assert!(b1.len() == b4.len());
        let b12 = match hamming_dist_bits(b1,b2) {
            Ok(d) => {
                (d as f64) / (keysize as f64)
            },
            Err(e) => {
                panic!(e);
            },
        };
        let b34 =  match hamming_dist_bits(b3,b4) {
            Ok(d) => {
                (d as f64) / (keysize as f64)
            },
            Err(e) => {
                panic!(e);
            },
        };
        results.push((keysize,(b12 + b34) / 2.0));
        //results.push((keysize,b12));
    }
    // sort by score
    results.sort_by( |a,b|  a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
    results
}

// Compute the hamming distance between two strings
fn hamming_dist_bits(s1 :&[u8], s2 :&[u8]) ->  Result<u32,XorError> {
    if s1.len() != s2.len() {
        return Err(XorError::DifferentSize(s1.len(),s2.len()));
    }
    let mut diff :u32 = 0;
    for (c1,c2) in s1.iter().zip(s2.iter()) {
        let mut b1 = *c1;
        let mut b2 = *c2;
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
    let s1 = b"this is a test";
    let s2 = b"wokka wokka!!!";
    let dist = 37;
    match hamming_dist_bits(s1,s2) {
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

#[test]
fn test_chi_square_pearson() {
    let t1 :&'static [u8] = b"aaaaaaaabccddddeeeeeeeeeeeeffgghhhhhhiiiiiiijkllllmmnnnnnnooooooopqrrrrrsssssstttttttttuuvwwxyyz";
    let t2  :&'static [u8] = b"aabccddddddeeeeeeeffgggghhhhhhiiiiiiijkkllllmmmnnnnnnooooooopqrrrrrsssssstttttuuuuvwwxyyzzzzz";
    let st1 = chi_square_pearson(t1,constants::FREQUENCY);
    let st2 = chi_square_pearson(t2,constants::FREQUENCY);
    assert!(st1 < st2);

}
