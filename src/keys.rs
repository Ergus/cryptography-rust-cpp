#![allow(dead_code)]

use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{One, Zero};

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
            let modinv: BigInt = (&p.0 - &q.0).modinv(&self.p).unwrap();
            s = (&p.1 - &p.1) * modinv % &self.p;
        }

        let x_r = (&s * &s - &p.0 - &p.0) % &self.p;
        let y_r = (&s * (&p.0 - &x_r) - &p.1) % &self.p;
        ((x_r + &self.p) % &self.p, (y_r + &self.p) % &self.p)
    }

    /// Generate a random number within a range
    pub fn generate_private_key(&mut self) -> BigInt {
        self.rng.gen_bigint_range(&BigInt::one(), &(self.n.clone() - BigInt::one()))
    }

   /// Perform scalar multiplication on the elliptic curve
    pub fn generate_public_key(&self, k: &BigInt) -> (BigInt, BigInt) {
        let mut result = (BigInt::zero(), BigInt::zero());
        let mut temp = self.g.clone();
        let mut k_bits = k.clone();

        let two: BigInt = 2.to_bigint().unwrap();

        while k_bits > BigInt::zero() {
            if &k_bits % &two == BigInt::one() {
                if result == (BigInt::zero(), BigInt::zero()) {
                    result = temp.clone();
                } else {
                    result = self.add_points(&result, &temp);
                }
            }
            temp = self.add_points(&temp, &temp);
            k_bits /= &two;
        }
        result
    }
}

#[cfg(test)]
mod test_keys {

    use super::*;
    //use cxx::let_cxx_string;
    use num_traits::Num;

    #[test]
    fn test_keys_rust() {

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
}
