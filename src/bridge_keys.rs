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

    #[cxx_name = "modInverseRust"]
    fn modInverse(
        a: &str,
        b: &str
    ) -> String;

    #[cxx_name = "scalarMultRust"]
    fn scalarMult(
        self: &EllipticCurve,
        P: &RustPoint,
        privateKey: &str
    ) -> RustPoint;
}
}

#[cfg(test)]
mod test_keys {

    use super::*;

    //use cxx::let_cxx_string;
    fn build_curve() -> cxx::UniquePtr<ffi::EllipticCurve>
    {
        let p: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        let a: &str = "0";
        let b: &str = "7";
        let n: &str = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let g = ffi::RustPoint{
            x: "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_string(),
            y: "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".to_string()
        };

        ffi::new(p, a, b, n, g, 5)
    }

    #[test]
    fn test_scalarmult_cxx()
    {
        let curve = build_curve();

        let p1 = ffi::RustPoint{
            x: "55066263022277343669578718895168534326250603453777594175500187360389116729240".to_string(),
            y: "32670510020758816978083085130507043184471273380659243275938904335757337482424".to_string()
        };

        let mult1 = curve.scalarMult(&p1, "9329907417039784576193289564026082738356516376004064111588951100120578211561");

        assert_eq!(mult1.x, "13255332944095317743365457951593438056358197283853040361054433460325789958939");
        assert_eq!(mult1.y, "19232106384549326684482202234590920947423692687234453473869945444749204252360");

        // Test another point

        let p2 = ffi::RustPoint{
            x: "54609349765814448718547960780397926716369689945570650172108049801429130973471".to_string(),
            y: "87446463567624540407413009967735707937419667663481099986997902514538910950850".to_string()
        };

        let mult2 = curve.scalarMult(&p2, "26469818958866652270687964108165471502529280030151630022280853366501018060089");

        assert_eq!(mult2.x, "10832260848141056500041504337524510254060096982033552532875360709844280160192");
        assert_eq!(mult2.y, "30181146142589002118874965738111095223489103249095720455546205218568118548357");

    }

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
        let curve = build_curve();

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
