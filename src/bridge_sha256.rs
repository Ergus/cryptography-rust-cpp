#![allow(dead_code)]

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
	include!("rust-sha256/include/sha256.h");

    #[cxx_name = "sha256_wrapper_raw"]
    fn sha256_cxx_raw(message: &[u8]) -> [u8; 32];

    #[cxx_name = "sha256_wrapper_str"]
    fn sha256_cxx_str(message: &str) -> String;
    }
}

#[cfg(test)]
mod test_sha256 {

    use super::*;
    use cxx::let_cxx_string;

    #[test]
    fn hello_world_cxx_raw_bytes()
    {
        let hash = ffi::sha256_cxx_raw(b"hello world");

        assert_eq!(hash, [0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d,
            0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7,
            0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84,
            0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9]);
    }

    #[test]
    fn hello_world_cxx_raw_str()
    {
        let_cxx_string!(greet = "hello world");

        let hash = ffi::sha256_cxx_raw(greet.as_bytes());

        assert_eq!(hash, [0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d,
            0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7,
            0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84,
            0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9]);
    }

    #[test]
    fn hello_world_cxx_str_str()
    {
        let hash = ffi::sha256_cxx_str("hello world");
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

}
