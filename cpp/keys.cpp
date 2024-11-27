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
