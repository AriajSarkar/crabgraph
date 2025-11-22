#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = FastLanesImproved::new(key, nonce);

        let mut buffer = vec![0u8; 1024];
        for i in 0..buffer.len() {
            buffer[i] = (i % 255) as u8;
        }
        let original = buffer.clone();

        let tag = cipher.encrypt_in_place(&mut buffer);
        assert_ne!(buffer, original);

        let tag2 = cipher.decrypt_in_place(&mut buffer);
        assert_eq!(buffer, original);
        assert_eq!(tag, tag2);
    }

    #[test]
    fn test_dispatch_choice_small() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = FastLanesImproved::new(key, nonce);

        assert_eq!(cipher.get_backend(), Backend::Auto);
        assert_eq!(cipher.choose_backend(1), Backend::Scalar);
        assert_eq!(cipher.choose_backend(64), Backend::Scalar);
        assert_eq!(cipher.choose_backend(256), Backend::Scalar);
    }

    #[test]
    fn test_dispatch_choice_large() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = FastLanesImproved::new(key, nonce);

        let expected = if is_x86_feature_detected!("avx2") {
            Backend::Avx2
        } else {
            Backend::Scalar
        };

        assert_eq!(cipher.choose_backend(257), expected);
        assert_eq!(cipher.choose_backend(1024), expected);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_auto() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let cipher = FastLanesImproved::new(key, nonce);

        for size in [250, 256, 257, 300] {
            let mut buffer = vec![0u8; size];
            for i in 0..size {
                buffer[i] = i as u8;
            }
            let original = buffer.clone();

            cipher.encrypt_in_place(&mut buffer);
            cipher.decrypt_in_place(&mut buffer);

            assert_eq!(buffer, original, "Failed at size {}", size);
        }
    }
}
