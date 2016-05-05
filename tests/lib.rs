extern crate cryptopals;
extern crate rustc_serialize as serialize;

#[cfg(test)]
mod tests {
    use cryptopals::*;
    use serialize::hex::FromHex;
    use serialize::hex::ToHex;


    #[test]
    fn set1_exo1() {
        let test = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").hex_to_bytes();
        let result = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert!(result == test.to_base64());
    }

    #[test]
    fn set1_exo2() {
        let test2 = String::from("1c0111001f010100061a024b53535009181c").hex_to_bytes(); 
        let test2_xor = String::from("686974207468652062756c6c277320657965").hex_to_bytes();
        let result2 = "746865206b696420646f6e277420706c6179";
        match xor_fixed(&test2,&test2_xor) {
            Ok(v) => 
                assert!(result2 == &v.to_hex()),
                Err(XorError::DifferentSize(a,b)) => println!("different size {} vs {}",a,b),
            _ => panic!("wow"),
        }
    }

    #[test]
    fn set1_exo5()  {
        // Test 3
        let test3 = String::from("Burning 'em, if you ain't quick and nimble");
        let key3 = String::from("ICE");
        let encrypted = xor_repeat(&test3.as_bytes(),&key3.as_bytes());
        assert!(encrypted.to_hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20");
    }

    #[test]
    fn set1_exo3() {
        let test3 = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").from_hex().unwrap();
        let test3Str = String::from_utf8(test3).unwrap();
        let (plain,key) = decrypt_single_xor(&test3Str,constants::FREQUENCY);
        let testResult = &"Cooking MC's like a pound of bacon";
        //println!("key = {} => {}",key,plain);
        assert_eq!(key,'X');
        assert!(&plain == testResult);
    }

}

