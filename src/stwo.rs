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

pub fn cbc_decrypt(cipher :&[u8],key :&[u8], iv :&[u8]) -> Result<Vec<u8>,BlockError> {
    if iv.len() != constants::AesBlockSize {
        return Err(BlockError::WrongIvSize(iv.len(),constants::AesBlockSize))
    }
    let mut xor_i = iv;
    let mut final_result = Vec::<u8>::new(); 
    for chunk in cipher.chunks(constants::AesBlockSize) {
        let result = match sone::decrypt_aes_ecb_nopad(chunk,key) { 
            Err(e) => return Err(BlockError::Symmetric(e)),
            Ok(r) => r,
        }; 
        let xored = match xor::xor_fixed(&result,xor_i) {
            Ok(b) => b,
            //Err(e) => return Err(BlockError::XorError(e)),
            // TODO check the pattern matching expansion doc to embed a XorError inside a
            // BlockError
            Err(x) => return Err(BlockError::Xor(x)),
        };
        final_result.extend(xored);
        xor_i = chunk;
    }

    return Ok(final_result)
}
