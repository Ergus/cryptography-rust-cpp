#pragma once

#include <gmpxx.h>
#include "rust/cxx.h"
#include <cassert>
#include <memory>
#include "sha256.h"

struct Point {
	rust::String x, y;
};

// Private Key: e70686214fdd53e3d94704ad90015c324e130559fcdd5a1ef8a3e5a6d68d9079
// Public Key: (84425eb8e32205a5f28c00a8fbe835b8ac95aebfa7342f53511b852c17df4763,
//              a2c1e9543181086806617c6d5fc1002e3d092cea8bd7f1cdb34980aaf7c76102)
class EllipticCurve {

	const mpz_class p; // Prime field
	const mpz_class a; // Curve coefficient a
	const mpz_class b; // Curve coefficient b
	const mpz_class n; // Order of the curve
	const std::pair<mpz_class, mpz_class> G; // Generator point
	mutable gmp_randclass rng;

	static inline mpz_class modInverse(const mpz_class& a, const mpz_class& m)
	{
		mpz_class inv;
		int invertible = mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
		assert(invertible);

		return inv;
	}

	friend rust::String modInverseRust(const rust::Str a, const rust::Str m);

	inline std::pair<mpz_class, mpz_class> scalarMult(
		const std::pair<mpz_class, mpz_class>& P,
		mpz_class privateKeyCopy
	) const {

		std::pair<mpz_class, mpz_class> result = {0, 0};
		std::pair<mpz_class, mpz_class> temp = P;

		mpz_class two(2);

		while (privateKeyCopy > 0) {
			if (privateKeyCopy % 2 == 1) {
				result = (result.first == 0 && result.second == 0)
					? temp
					: addPoints(result, temp);
			}
			temp = addPoints(temp, temp);
			privateKeyCopy /= two;
		}

		return result;
	}


	inline std::pair<mpz_class, mpz_class> addPoints(
		const std::pair<mpz_class, mpz_class>& P,
		const std::pair<mpz_class, mpz_class>& Q
	) const {

		mpz_class s;

		if (P == Q) {
			s = (3 * P.first * P.first + a) * modInverse(2 * P.second, p) % p;
		} else {
			mpz_class modinv = modInverse(Q.first - P.first, p);
			s = (Q.second - P.second) * modinv % p;
		}

		mpz_class x_r = (s * s - P.first - Q.first) % p;
		mpz_class y_r = (s * (P.first - x_r) - P.second) % p;

		std::pair<mpz_class, mpz_class> result = { (x_r + p) % p, (y_r + p) % p };

		return result;
	}

	mpz_class hashMessage(const std::string& message) const
	{
		std::string hash = sha256(message);
		return mpz_class(hash, 16);
	}

	// ECDSA Signing
	std::pair<mpz_class, mpz_class> signMessage(
		const std::string& message,
		const mpz_class &privateKey
	) const {
		mpz_class z = EllipticCurve::hashMessage(message);

		mpz_class k = generatePrivateKey();
		std::pair<mpz_class, mpz_class> R = generatePublicKey(k);

		mpz_class r = R.first % n ;
		mpz_class s = (modInverse(k, n) * (z + r * privateKey)) % n;
		return {r, s};
	}

	// ECDSA Verification
	bool verifySignature(
		const std::string& message,
		const std::pair<mpz_class, mpz_class>& signature,
		const std::pair<mpz_class, mpz_class>& publicKey
	) const {

		mpz_class z = hashMessage(message);

		mpz_class w = modInverse(signature.second, n);

		mpz_class u1 = (z * w) % n;
		mpz_class u2 = (signature.first * w) % n;

		std::pair<mpz_class, mpz_class> P1 = scalarMult(G, u1);
		std::pair<mpz_class, mpz_class> P2 = scalarMult(publicKey, u2);

		std::pair<mpz_class, mpz_class> P = addPoints(P1, P2);

		return P.first % n == signature.first;
	}

public:

	inline EllipticCurve(
		mpz_class p,
		mpz_class a,
		mpz_class b,
		mpz_class n,
		std::pair<mpz_class, mpz_class> G,
		unsigned long seed
	) : p(p), a(a), b(b), n(n), G(G), rng(gmp_randinit_default)
	{
		rng.seed(seed);
	}

	inline std::pair<mpz_class, mpz_class> generatePublicKey(
		const mpz_class &privateKey
	) const {
		return scalarMult(G, privateKey);
	}

	inline mpz_class generatePrivateKey() const
	{
		// Generate a random number in the range [1, n]
		return 1 + rng.get_z_range(n - 1);
	}

	// Rust functions ================================

	inline Point scalarMultRust(const Point& P, rust::Str privateKey) const
	{
		std::pair<mpz_class, mpz_class> point {
			mpz_class(static_cast<std::string>(P.x)),
			mpz_class(static_cast<std::string>(P.y)),
		};

		mpz_class priv_key(static_cast<std::string>(privateKey));

		auto mult = this->scalarMult(point, priv_key);
		return {mult.first.get_str(), mult.second.get_str()}; // Convert points to string
	}

	inline rust::String generatePrivateKeyRust() const
	{
        return generatePrivateKey().get_str();
    }

    inline Point generatePublicKeyRust(const rust::Str private_key) const
	{
        mpz_class priv_key(static_cast<std::string>(private_key));
        auto public_key = generatePublicKey(priv_key);
        return {public_key.first.get_str(), public_key.second.get_str()}; // Convert points to string
    }

	inline Point signMessageRust(
		const rust::Str message,
		const rust::Str private_key
	) const {
		mpz_class priv_key(static_cast<std::string>(private_key));

		std::pair<mpz_class, mpz_class> signature = signMessage(
			static_cast<std::string>(message),
			std::move(priv_key)
		);

		return {signature.first.get_str(), signature.second.get_str()}; // Convert fignature to string
	}

	// ECDSA Verification
	bool verifySignatureRust(
		const rust::Str message,
		const Point& signature,
		const Point& publicKey
	) const {

		std::pair<mpz_class, mpz_class> sig {
			mpz_class(static_cast<std::string>(signature.x)),
			mpz_class(static_cast<std::string>(signature.y)),
		};

		std::pair<mpz_class, mpz_class> pub {
			mpz_class(static_cast<std::string>(publicKey.x)),
			mpz_class(static_cast<std::string>(publicKey.y)),
		};

		return verifySignature(static_cast<std::string>(message), sig, pub);
	}
};


// Functions wrappers for rust (needed to pass the values as strings)
// Wrapper constructor for Rust
inline std::unique_ptr<EllipticCurve> EllipticCurveNewRust(
        const rust::Str p,
        const rust::Str a,
        const rust::Str b,
        const rust::Str n,
        const Point G,
		unsigned long seed
) {
	return std::make_unique<EllipticCurve>(
		mpz_class(static_cast<std::string>(p)),
		mpz_class(static_cast<std::string>(a)),
		mpz_class(static_cast<std::string>(b)),
		mpz_class(static_cast<std::string>(n)),
		std::make_pair<mpz_class, mpz_class>(
			mpz_class(static_cast<std::string>(G.x)),
			mpz_class(static_cast<std::string>(G.y))
		),
		seed
	);
}

inline rust::String modInverseRust(const rust::Str a, const rust::Str m)
{

	mpz_class mpz_a(static_cast<std::string>(a));
	mpz_class mpz_m(static_cast<std::string>(m));

	return EllipticCurve::modInverse(mpz_a, mpz_a).get_str();
}
