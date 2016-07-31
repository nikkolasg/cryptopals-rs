extern crate crypto;
extern crate rand;

use self::crypto::symmetriccipher::SymmetricCipherError;
use self::crypto::aes;
use self::crypto::blockmodes;
use self::crypto::buffer;
use self::crypto::buffer::{BufferResult,WriteBuffer,ReadBuffer};

use self::rand::{ Rng, OsRng };

use constants;
use sone;
use xor;

#[derive(Debug)]
pub enum BlockError {
    WrongIvSize(usize,usize),
    Symmetric(SymmetricCipherError),
    Xor(xor::XorError),
    Unknown,
}

#[derive(Debug)]
pub enum BlockMode {
    ECB,
    CBC,
}

pub fn random_bytes(len :usize) ->Vec<u8> {
    let mut rng = OsRng::new().ok().unwrap();
    rng.gen_iter::<u8>().take(len).collect::<Vec<u8>>()
}

pub fn random_u32() -> u32 {
    let mut rng = OsRng::new().ok().unwrap();
    rng.next_u32()
}

// Add *padding_length* bytes before and after the plaintext, choose a random BlockMode,
// encrypt the message with it and return the message and the blockmode.
pub fn blackbox_aes_encrypt(msg :&[u8]) -> Result<(Vec<u8>,BlockMode),BlockError> {
    let padding_length = ((random_u32() % 10) + 5) as usize;
    let new_length = msg.len() + 2 * padding_length;
    let mut padded  = vec![0;new_length];
    padded[padding_length..new_length-padding_length].clone_from_slice(msg);
    fill_random(&mut padded[0..padding_length]);
    fill_random(&mut padded[msg.len()..]);

    let key = random_bytes(16);

    let block_mode = match (rand::random::<u8>() % 2 as u8) {
        0 => BlockMode::ECB,
        1 => BlockMode::CBC,
        _ => panic!("the math we know are wrong"),
    };

    println!("New msg: {:?}",padded);
    println!("Blockmode chosen: {:?}",block_mode);

    match block_mode {
        BlockMode::ECB => {
            match sone::encrypt_aes_ecb_pkcs(&padded,&key) { 
                Ok(cipher) => return Ok((cipher,BlockMode::ECB)),
                Err(e) => return Err(BlockError::Symmetric(e)),
            };
        },
        BlockMode::CBC =>  {
            // generate random IV
            let iv = random_bytes(16);
            match cbc_encrypt(&padded,&key,&iv) {
                Ok(cipher) => return Ok((cipher,BlockMode::CBC)),
                Err(e) => return Err(e),
            }
        },
    }
}

fn fill_random(mut buff :&mut [u8]) {
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut buff);
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

pub fn cbc_encrypt(data :&[u8],key :&[u8], iv :&[u8]) -> Result<Vec<u8>,BlockError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true);
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => { },
            Err(SymmetricCipherError::InvalidPadding) => return Err(BlockError::Symmetric(SymmetricCipherError::InvalidPadding)),
            Err(SymmetricCipherError::InvalidLength) => return Err(BlockError::Symmetric(SymmetricCipherError::InvalidLength)),
        };
    }
    Ok(final_result)
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

#[test]
fn test_pkcs_padding() {
    let mut rng = OsRng::new().ok().unwrap();
    let mut m_under :[u8;14] = [0;14];
    let mut m_exact :[u8;16] = [0;16];
    let mut m_over :[u8;17] = [0;17];
    rng.fill_bytes(&mut m_under);
    rng.fill_bytes(&mut m_exact);
    rng.fill_bytes(&mut m_over);

    let under_p = &pkcs7_padding(&m_under[..],constants::AesBlockSize);
    let exact_p = &pkcs7_padding(&m_exact[..],constants::AesBlockSize);
    let over_p  = &pkcs7_padding(&m_over[..],constants::AesBlockSize);

    let under_u :&[u8] = &pkcs7_remove(under_p);
    let exact_u :&[u8] = &pkcs7_remove(exact_p);
    let over_u :&[u8] =  &pkcs7_remove(over_p);

    assert_eq!(under_u,&m_under[..]);
    assert_eq!(exact_u,&m_exact[..]);
    assert_eq!(over_u,&m_over[..]);
}

#[test]
fn test_random_bytes() {
    let mut b1 = random_bytes(16);
    let zero = [0u8;16];
    assert_eq!(b1.len(),zero.len());
    if b1 == zero {
        assert!(false,"random bytes returns 0");
    }
}

#[test]
fn test_aes_cbc() {
    let mut key = random_bytes(16);
    let mut iv = random_bytes(16);
    let message = random_bytes(16 * 4 + 7);

    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let cipher = cbc_encrypt(&message,&key,&iv).ok().unwrap();
    let plain = match cbc_decrypt(&cipher,&key,&iv) {
        Ok(p) => p,
        Err(e) => {
            println!("Error decrypting: {:?}",e);
            assert!(false);
            return
        }
    };

    assert_eq!(&message[..],&plain[..]);
    
}
