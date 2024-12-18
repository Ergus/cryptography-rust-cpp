#pragma once

#include <gmpxx.h>
#include "rust/cxx.h"
#include <cassert>
#include <memory>

// Private Key: e70686214fdd53e3d94704ad90015c324e130559fcdd5a1ef8a3e5a6d68d9079
// Public Key: (84425eb8e32205a5f28c00a8fbe835b8ac95aebfa7342f53511b852c17df4763, a2c1e9543181086806617c6d5fc1002e3d092cea8bd7f1cdb34980aaf7c76102)

struct Point {
	rust::String x, y;
};

class EllipticCurve {

	const mpz_class p; // Prime field
	const mpz_class a; // Curve coefficient a
	const mpz_class b; // Curve coefficient b
	const mpz_class n; // Order of the curve
	const std::pair<mpz_class, mpz_class> G; // Generator point
	mutable gmp_randclass rng;

	mpz_class modInverse(const mpz_class& x) const {
		mpz_class inv;
		int invertible = mpz_invert(inv.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
		assert(invertible);
		return inv;
	}

	std::pair<mpz_class, mpz_class> addPoints(
		const std::pair<mpz_class, mpz_class>& P,
		const std::pair<mpz_class, mpz_class>& Q
	) const;

public:

	EllipticCurve(
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

	mpz_class generatePrivateKey() const;

    std::pair<mpz_class, mpz_class> generatePublicKey(
		mpz_class privateKey
	) const;


	inline rust::String generatePrivateKeyRust() const
	{
        return generatePrivateKey().get_str();
    }

    Point generatePublicKey(const rust::Str private_key) const
	{
        mpz_class priv_key(static_cast<std::string>(private_key));
        auto public_key = generatePublicKey(priv_key);
        return {public_key.first.get_str(), public_key.second.get_str()}; // Convert points to string
    }

};


// Functions wrappers for rust (needed to pass the values as strings)
// Wrapper constructor for Rust
inline std::unique_ptr<EllipticCurve> mynew(
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
		std::make_pair<mpz_class, mpz_class>(mpz_class(static_cast<std::string>(G.x)), mpz_class(static_cast<std::string>(G.y))),
		seed
	);
}
