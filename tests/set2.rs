extern crate cryptopals;
extern crate rustc_serialize as serialize;

#[cfg(test)]
mod tests {
    use cryptopals::stwo::*;
    use serialize::hex::ToHex;

    #[test]
    fn set2_exo9() {
        let input = String::from("YELLOW SUBMARINE");
        let output = pkcs7_padding(input.as_bytes(),20);
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_hex(); 
        let output_hex = output.to_hex();
        assert_eq!(expected,output_hex);
    }
}
