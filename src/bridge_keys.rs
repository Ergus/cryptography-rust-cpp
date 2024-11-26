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
    //use cxx::let_cxx_string;

    #[test]
    fn test_keys_string() {

        let p: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let a: &str = "0";
        let b: &str = "7";
        let n: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let g = ffi::RustPoint{
            x: "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_string(),
            y: "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".to_string()
        };

        let curve = ffi::mynew(p, a, b, n, g);


        let _private_key = curve.generatePrivateKey2("1", n, 5);
    }
}
