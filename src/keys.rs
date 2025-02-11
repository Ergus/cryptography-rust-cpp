#![allow(dead_code)]

use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{Num, One, Zero};

/// Struct representing an elliptic curve
struct EllipticCurve {
    p: BigInt,                     // Prime modulus
    a: BigInt,                     // Curve coefficient a
    b: BigInt,                     // Curve coefficient b
    n: BigInt,                     // Order of the curve
    g: (BigInt, BigInt),          // Generator point (x, y)
    rng: rand::rngs::ThreadRng,
}

impl EllipticCurve {

    fn scalar_mult(
        &self,
        point: &(BigInt, BigInt),
        private_key: &BigInt
    ) -> (BigInt, BigInt) {
        let mut result = (BigInt::zero(), BigInt::zero());
        let mut temp = point.clone();
        let mut private_key_copy = private_key.clone();
        let two: BigInt = 2.to_bigint().unwrap();

        while private_key_copy > BigInt::zero() {
            if &private_key_copy % &two == BigInt::one() {
                if result == (BigInt::zero(), BigInt::zero()) {
                    result = temp.clone();
                } else {
                    result = self.add_points(&result, &temp);
                }
            }
            temp = self.add_points(&temp, &temp);
            private_key_copy /= &two;
        }
        result
    }

    /// Add two points on the elliptic curve
    fn add_points(
        &self,
        p: &(BigInt, BigInt),
        q: &(BigInt, BigInt),
    ) -> (BigInt, BigInt) {

        let s;

        if p == q {// Point doubling
            let modinv: BigInt = (&p.1 + &p.1).modinv(&self.p).unwrap();
            s = (3.to_bigint().unwrap() * &p.0 * &p.0 + &self.a) * modinv % &self.p;
        } else { // Point addition
            let modinv: BigInt = (&q.0 - &p.0).modinv(&self.p).unwrap();
            s = (&q.1 - &p.1) * modinv % &self.p;
        }

        let x_r = (&s * &s - &p.0 - &q.0) % &self.p;
        let y_r = (&s * (&p.0 - &x_r) - &p.1) % &self.p;

        ((x_r + &self.p) % &self.p, (y_r + &self.p) % &self.p)
    }

    /// Generate a random number within a range
    pub fn generate_private_key(&mut self) -> BigInt {
        self.rng.gen_bigint_range(&BigInt::one(), &(self.n.clone() - BigInt::one()))
    }

   /// Perform scalar multiplication on the elliptic curve
    pub fn generate_public_key(&self, k: &BigInt) -> (BigInt, BigInt)
    {
        self.scalar_mult(&self.g, k)
    }

    fn hash_message(message: &str) -> BigInt
	{
		let hash = crate::sha256::sha256_rust_str(message);
		BigInt::from_str_radix(hash.as_str(), 16).unwrap()
	}

	// ECDSA Signing
	fn sign_message(&mut self, message: &str, private_key: &BigInt) -> (BigInt, BigInt)
    {
		let z: BigInt = Self::hash_message(message);

		let k: BigInt = self.generate_private_key();
		let r_pair: (BigInt, BigInt) = self.generate_public_key(&k);

		let r: BigInt = r_pair.0 % &self.n ;

		let s: BigInt = (k.modinv(&self.n).unwrap() * (z + &r * private_key)) % &self.n;
		return (r, s);
	}

	// // ECDSA Verification
	fn verify_signature(
        &mut self, message: &str,
		signature: &(BigInt, BigInt),
		public_key: &(BigInt, BigInt)
	) -> bool {
		let z: BigInt = Self::hash_message(message);

		let w: BigInt = signature.1.modinv(&self.n).unwrap();

		let u1: BigInt = (z * &w) % &self.n;
		let u2: BigInt = (&signature.0 * &w) % &self.n;

		let p1: (BigInt, BigInt) = self.scalar_mult(&self.g, &u1);
		let p2: (BigInt, BigInt) = self.scalar_mult(&public_key, &u2);
		let p: (BigInt, BigInt) = self.add_points(&p1, &p2);

        println!("{} vs {}", &p.0 % &self.n, signature.0);

		return p.0 % &self.n == signature.0;
	}
}

#[cfg(test)]
mod test_keys {

    use std::str::FromStr;

    use super::*;
    //use cxx::let_cxx_string;
    use num_traits::Num;

    fn build_curve() -> EllipticCurve
    {
        let p: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
        let a = BigInt::zero();
        let b = BigInt::from(7u32);
        let n = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16).unwrap();
        let g = (
            BigInt::from_str_radix("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
            BigInt::from_str_radix("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
        );

        EllipticCurve { p, a, b, n, g, rng: rand::thread_rng() }
    }

    #[test]
    fn test_scalarmult_rust()
    {
        let curve = build_curve();

        let p1 = (
            BigInt::from_str("55066263022277343669578718895168534326250603453777594175500187360389116729240").unwrap(),
            BigInt::from_str("32670510020758816978083085130507043184471273380659243275938904335757337482424").unwrap()
        );

        let mult1 = curve.scalar_mult(
            &p1,
            &BigInt::from_str_radix("9329907417039784576193289564026082738356516376004064111588951100120578211561", 10).unwrap()
        );

        assert_eq!(mult1.0.to_str_radix(10), "13255332944095317743365457951593438056358197283853040361054433460325789958939");
        assert_eq!(mult1.1.to_str_radix(10), "19232106384549326684482202234590920947423692687234453473869945444749204252360");

        // Test another point

        let p2 = (
            BigInt::from_str("54609349765814448718547960780397926716369689945570650172108049801429130973471").unwrap(),
            BigInt::from_str("87446463567624540407413009967735707937419667663481099986997902514538910950850").unwrap()
        );

        let mult2 = curve.scalar_mult(
            &p2,
            &BigInt::from_str("26469818958866652270687964108165471502529280030151630022280853366501018060089").unwrap()
        );

        assert_eq!(mult2.0.to_str_radix(10), "10832260848141056500041504337524510254060096982033552532875360709844280160192");
        assert_eq!(mult2.1.to_str_radix(10), "30181146142589002118874965738111095223489103249095720455546205218568118548357");

    }

    #[test]
    fn test_keys_rust()
    {
        let p: BigInt = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
        let a = BigInt::zero();
        let b = BigInt::from(7u32);
        let n = BigInt::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16).unwrap();
        let g = (
        BigInt::from_str_radix("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
        BigInt::from_str_radix("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
        );

        let mut curve = EllipticCurve { p, a, b, n, g, rng: rand::thread_rng() };

        // Generate a private key
        let private_key = curve.generate_private_key();
        println!("Private Key: 0x{}", private_key.to_str_radix(16));

        // Generate a public key
        let public_key = curve.generate_public_key(&private_key);
        println!(
            "Public Key: (0x{}, 0x{})",
            public_key.0.to_str_radix(16),
            public_key.1.to_str_radix(16)
        );

    }


    #[test]
    fn test_signature_rust()
    {
        let mut curve = build_curve();

        // Generate a private key
        let private_key = curve.generate_private_key();
        println!("Private Key: 0x{}", private_key.to_str_radix(16));

        // Generate a public key
        let public_key = curve.generate_public_key(&private_key);
        println!(
            "Public Key: (0x{}, 0x{})",
            public_key.0.to_str_radix(16),
            public_key.1.to_str_radix(16)
        );

        let signature = curve.sign_message(
            "This is my message with random text, not important",
            &private_key
        );

        assert!(curve.verify_signature(
            "This is my message with random text, not important",
            &signature,
            &public_key
        ));

    }


}
