use std::collections::HashMap;

pub enum XorError {
    DifferentSize(usize,usize),
    Unbreakable,
}
// decrypt a cipher text that has been encrypted using a single byte key
// return the plaintext and key
pub fn decrypt_single_xor(cipher :&str,frequencies :&[f32]) -> (String,char) {
    let mut max :f32 = -1.0;
    let mut kc :char = '0';
    let mut plaintext :Vec<u8> = Vec::new();
    // try each letter of the ASCII Uppercase
    for i in 65u8..90 {
        if i > 90 && i < 97 {
            // skip non alphabetic characters
            continue;
        }
        // the key
        let key =  i as char;
        let decrypt = || cipher.chars().map( |x| x as u8).map( |x| x ^ i);
        let out = decrypt().collect::<Vec<u8>>();
        // determine frequency
        let mut freqs = decrypt().fold(HashMap::<u8,f32>::new(),
            |mut acc,ch| {
                *acc.entry(ch).or_insert(0.0) += 1.0;
                acc
            });

        //println!("freqs {:?} ",freqs);

        // chisquare test with english frequency
        let chi = freqs.iter().fold(0.0,|mut acc,(letter,freq)| { 
            let mut ascii :u8= (*letter) as u8;
            // no if its not a lettr
            if ascii > 64 && ascii <= 90 {
                ascii = ascii - 65;
            } else if ascii < 97 || ascii > 122 {
                return acc;
            } else {
                ascii = ascii - 97;
            }
            let freqEnglish = frequencies[ascii as usize] /  100.0;
            //println!("ASCII {} => idx {} = {}",(ascii+97) as char,ascii,freqEnglish);
            let textFreq = (*freq as f32)/ (cipher.len() as f32); // normalize
            acc += (textFreq - freqEnglish).powi(2) / freqEnglish;
            acc
        });
        if max > chi || max == -1.0 {
            max = chi;
            kc = key;
            //println!("Found better statistics chi {} => {}  => size({}) {:?}",chi,kc,cipher.len(),out);
            plaintext = out;
        }
    }
    let re = String::from_utf8(plaintext).unwrap();
    return (re,kc)
}


// xor a key against a message repeatedly
pub fn xor_repeat(msg :&[u8], key :&[u8]) -> Vec<u8> {
    let mut it = msg.iter();
    let mut idx :usize = 0;
    let mut out = Vec::with_capacity(msg.len());
    while let Some(by) = it.next()  {
        //println!("byte = {}, key = {}, idx = {}",by,key[idx],idx);
        out.push(by ^ key[idx]);
        idx = (idx+1)% key.len();
    }
    return out
}

// xor two slices  of same length
pub fn xor_fixed(b1 :&[u8],b2 :&[u8]) -> Result<Vec<u8>, XorError> {
    if b1.len() != b2.len() {
        return Err(XorError::DifferentSize(b1.len(),b2.len()));
        //    return Err();
    }
    let res :Vec<u8> = b1.iter().zip(b2).map(|(x1,x2)| x1 ^ x2).collect();
    return Ok(res);
}

