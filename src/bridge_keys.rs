#![allow(dead_code)]


#[cxx::bridge]
mod ffi {
    #[derive(Debug)]
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

    #[cxx_name = "EllipticCurveNewRust"]
    fn new(
        p: &str,
        a: &str,
        b: &str,
        n: &str,
        G: RustPoint,
        seed: u64
    ) -> UniquePtr<EllipticCurve>;

    #[cxx_name = "generatePrivateKeyRust"]
    fn generatePrivateKey(
        self: &EllipticCurve,
    ) -> String;

    /// Generate a public key given a private key.
    #[cxx_name = "generatePublicKeyRust"]
    fn generatePublicKey(
        self: &EllipticCurve,
        private_key: &str
    ) -> RustPoint;


    /// Sign a message and return the signature
    #[cxx_name = "signMessageRust"]
    fn signMessage(
        self: &EllipticCurve,
        message: &str,
        private_key: &str
    ) -> RustPoint;

    /// Generate a public key given a private key.
    #[cxx_name = "verifySignatureRust"]
    fn verifySignature(
        self: &EllipticCurve,
        message: &str,
        signature: &RustPoint,
        publicKey: &RustPoint
    ) -> bool;
}
}

#[cfg(test)]
mod test_keys {

    use super::*;
    //use cxx::let_cxx_string;

    #[test]
    fn test_keys_cxx()
    {

        let p: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let a: &str = "0";
        let b: &str = "7";
        let n: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let g = ffi::RustPoint{
            x: "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_string(),
            y: "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".to_string()
        };

        let curve = ffi::new(p, a, b, n, g, 5);

        let private_key: String = curve.generatePrivateKey();

        let public_key = curve.generatePublicKey(&private_key);

        println!("Private key: {}", private_key);
        println!("Public key: {:?}", public_key);
    }

    #[test]
    fn test_signature_cxx()
    {
        let p: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let a: &str = "0";
        let b: &str = "7";
        let n: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let g = ffi::RustPoint{
            x: "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_string(),
            y: "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".to_string()
        };

        let curve = ffi::new(p, a, b, n, g, 5);

        let private_key: String = curve.generatePrivateKey();

        let public_key = curve.generatePublicKey(&private_key);

        println!("Private key: {}", private_key);
        println!("Public key: {:?}", public_key);

        let signature = curve.signMessage(
            "This is my message with random text, not important",
            private_key.as_str()
        );

        assert!(curve.verifySignature(
            "This is my message with random text, not important",
            &signature,
            &public_key
        ));

    }
}
