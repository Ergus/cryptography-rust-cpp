#include "rust-sha256/include/keys.h"

#include <random>
#include <cassert>
#include <iostream>
// Private Key: e70686214fdd53e3d94704ad90015c324e130559fcdd5a1ef8a3e5a6d68d9079
// Public Key: (84425eb8e32205a5f28c00a8fbe835b8ac95aebfa7342f53511b852c17df4763, a2c1e9543181086806617c6d5fc1002e3d092cea8bd7f1cdb34980aaf7c76102);

std::pair<mpz_class, mpz_class> EllipticCurve::addPoints(
	const std::pair<mpz_class, mpz_class>& P,
	const std::pair<mpz_class, mpz_class>& Q
) const {
	mpz_class s;

	if (P == Q)
		s = (3 * P.first * P.first + a) * modInverse(2 * P.second) % p;
	else
		s = (Q.second - P.second) * modInverse(Q.first - P.first) % p;

	mpz_class x_r = (s * s - P.first - Q.first) % p;
	mpz_class y_r = (s * (P.first - x_r) - P.second) % p;
	return { (x_r + p) % p, (y_r + p) % p };
}

mpz_class EllipticCurve::generatePrivateKey() const
{
    // Generate a random number in the range [1, n]
    return 1 + rng.get_z_range(n - 1);
}

std::pair<mpz_class, mpz_class> EllipticCurve::generatePublicKey(
	mpz_class privateKey
) const {
	std::pair<mpz_class, mpz_class> result = {0, 0};
	std::pair<mpz_class, mpz_class> temp = G;

	while (privateKey > 0) {
		if (privateKey % 2 == 1) {
			result = (result.first == 0 && result.second == 0) ? temp : addPoints(result, temp);
		}
		temp = addPoints(temp, temp);
		privateKey /= 2;
	}
	return result;
}


// int main()
// {
//     // SECP256k1 curve parameters
//     mpz_class p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
//     mpz_class a(0);
//     mpz_class b(7);
//     mpz_class n("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
//     std::pair<mpz_class, mpz_class> G(
//         mpz_class("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
//         mpz_class("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
//     );

//     EllipticCurve curve(p, a, b, n, G);

//     // Generate private key
//     //mpz_class privateKey = generateRandomNumber(1, n - 1, std::random_device{}());
// 	mpz_class privateKey = EllipticCurve::generateRandomNumber(1, n - 1, 5);
//     std::cout << "Private Key: " << privateKey.get_str(16) << "\n";

//     // Generate public key
//     std::pair<mpz_class, mpz_class> publicKey = curve.scalarMult(privateKey, G);
//     std::cout << "Public Key: (" << publicKey.first.get_str(16) << ", " << publicKey.second.get_str(16) << ")\n";

//     return 0;
// }
