#![allow(dead_code)]


#[cxx::bridge]
mod ffi {

    struct RustPoint {
        x: String,
        y: String,
    }

    unsafe extern "C++" {
    include!("rust-sha256/include/keys.h");

    // Import the `EllipticCurve` class.
    type EllipticCurve;

    /// Declare that the Rust struct corresponds to the C++ struct `Point`.
    #[cxx_name = "Point"]
    type RustPoint;


    fn mynew(
        p: &str,
        a: &str,
        b: &str,
        n: &str,
        G: RustPoint
    ) -> UniquePtr<EllipticCurve>;

    fn generatePrivateKey2(
        self: &EllipticCurve,
        min: &str,
        max: &str,
        seed: u64
    ) -> String;

    /// Generate a public key given a private key.
    fn generatePublicKey2(
        self: &EllipticCurve,
        private_key: &str
    ) -> RustPoint;
}
}

#[cfg(test)]
mod test_keys {

    use super::*;
    use cxx::let_cxx_string;

    #[test]
    fn test_keys_string() {
        
    }
}
