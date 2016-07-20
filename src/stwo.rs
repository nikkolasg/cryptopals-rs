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
