pub enum XorError {
    DifferentSize(usize,usize),
}

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

pub fn xor_fixed(b1 :&[u8],b2 :&[u8]) -> Result<Vec<u8>, XorError> {
    if b1.len() != b2.len() {
        return Err(XorError::DifferentSize(b1.len(),b2.len()));
        //    return Err();
    }
    let res :Vec<u8> = b1.iter().zip(b2).map(|(x1,x2)| x1 ^ x2).collect();
    return Ok(res);
}

