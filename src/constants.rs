// frequency letters
pub static FREQUENCY :&'static [f32]  = &[8.167,1.492,2.782,  
                    4.253,12.70,2.228,2.015,6.094,6.966,  
                    0.153,0.772,4.025,2.406,6.749,7.507,
                    1.929,0.095,5.987,6.327,9.056,2.758,
                    0.978,2.361,0.150,1.974,0.074];

// a static array of bytes representing chars
pub const BASE64 :&'static [u8]= b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

#[test]
fn test_frequency_length() {
    assert!(FREQUENCY.len() == 26);
}
