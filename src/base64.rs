use crate::err::Res;
use openssl::base64::{decode_block, encode_block};

pub fn base64url_decode(encoded: impl AsRef<str>) -> Res<Vec<u8>> {
    let mut unpadded = encoded.as_ref().replace('-', "+").replace('_', "/");
    while unpadded.len() % 4 != 0 {
        unpadded.push('=')
    }
    Ok(decode_block(&unpadded)?)
}

pub fn base64url_encode(plain: impl AsRef<[u8]>) -> String {
    encode_block(plain.as_ref())
        .replace('+', "-")
        .replace('/', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_decode_is_inverse_of_encode() {
        let plaintext = b"encode and decode are inverses of each other";
        let encoded = base64url_encode(plaintext);
        let decoded = base64url_decode(encoded);
        assert_eq!(plaintext, decoded.unwrap().as_slice());
    }

    #[test]
    fn base64url_decode_might_fail() {
        let plaintext = "***";
        assert!(base64url_decode(plaintext).is_err());
    }
}
