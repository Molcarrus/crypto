use crate::aes::{aes_ecb_enc, AesType};

#[cfg(test)]
mod aes_mp_tests {
    use super::*;
    #[test]
    fn aes_mp_test() {
        let msg: [u8; 22] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x01, 0x01, 0x53, 0x48, 0x45, 0x00
        ]; 
        let mut res: String = String::new();

        let key_derived: [u8; 16] = mp_compression(&msg);
        dbg!(&key_derived);
        for byte in key_derived.clone() {
            res.push_str(&format!("{:02x}", byte))
        }
        assert_eq!(res, "118a46447a770d87828a69c222e2d17e");
    }
}

pub fn mp_compression(msg: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    let bits_rem: usize = (msg.len() * u8::BITS as usize) % 128;
    let mut msg_padding: Vec<u8> = msg.to_vec();
    let k: usize = if bits_rem + 1 > 88 {
        128 - 1 - bits_rem + 128
    } else if bits_rem + 1 < 88 {
        88 - 1 - bits_rem
    } else {
        0
    };

    msg_padding.push(0x80);

    let zero_to_pad: usize = (k - 7) / u8::BITS as usize;
    for _ in 0..zero_to_pad {
        msg_padding.push(0x00);
    }
    let len_be_bytes: [u8; 8] = (msg.len() * u8::BITS as usize).to_be_bytes();

    let (_, left) = len_be_bytes.split_at(3);

    msg_padding.append(&mut left.to_vec());

    let chunks = msg_padding.chunks(16);
    for chunk in chunks {
        let enc: Vec<u8> = aes_ecb_enc(&chunk.to_vec(), &out, &AesType::AES128);
        for (i, byte) in chunk.iter().enumerate() {
            out[i] = enc[i] ^ byte ^ out[i];
        }
    }

    out
}