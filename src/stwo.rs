extern crate crypto;
use self::crypto::symmetriccipher::SymmetricCipherError;

use constants;
use sone;
use xor;

#[derive(Debug)]
pub enum BlockError {
    WrongIvSize(usize,usize),
    Symmetric(SymmetricCipherError),
    Xor(xor::XorError),
}


// pkcs7_padding will pad the given buffer using pkcs7 standard according 
// to the given block size
pub fn pkcs7_padding(buffer :&[u8], bsize :usize) -> Vec<u8> {
    let modulo = buffer.len() % bsize; 
    let addedOffset = match modulo {
        0 => bsize,
        e => bsize - e,
    };

    let mut padded = vec![0;buffer.len() + addedOffset];
    padded[..buffer.len()].clone_from_slice(buffer);

    // write the padding
    for i in 0..addedOffset {
        padded[buffer.len()+i] = addedOffset as u8;
    }
    return padded;
}

// Remove the pkcs7 padding -> truncate the buffer
fn pkcs7_remove(buff :&[u8]) -> Vec<u8> {
    let last = *buff.last().unwrap();
    for &b in buff.iter().rev().take(last as usize) {
        if b != last {
            panic!("pkcs7_remove given invalid buffer {} vs last {}",b,last);
        }
    }
    buff.iter().take(buff.len()-last as usize).map(|&i| i).collect::<Vec<u8>>()
}

pub fn cbc_decrypt(cipher :&[u8],key :&[u8], iv :&[u8]) -> Result<Vec<u8>,BlockError> {
    if iv.len() != constants::AesBlockSize {
        return Err(BlockError::WrongIvSize(iv.len(),constants::AesBlockSize))
    }
    let mut xor_i = iv;
    let mut final_result = Vec::<u8>::new(); 
    let last_block_i = (cipher.len() / constants::AesBlockSize) - 1;
    for (i,chunk) in cipher.chunks(constants::AesBlockSize).enumerate() {
        let result = match sone::decrypt_aes_ecb_nopad(chunk,key) {  
            Err(e) => return Err(BlockError::Symmetric(e)),
            Ok(r) => r,
        }; 
        let mut xored = match xor::xor_fixed(&result,xor_i) {
            Ok(b) => b,
            // TODO check the pattern matching expansion doc to embed 
            // a XorError inside a BlockError directly (no field Xor)
            Err(x) => return Err(BlockError::Xor(x)),
        };
        if i == last_block_i  {
            xored = pkcs7_remove(&xored)
        }
        final_result.extend(xored);
        xor_i = chunk;

    }

    return Ok(final_result)
}
