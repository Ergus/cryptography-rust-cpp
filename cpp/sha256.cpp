#include "sha256.h"

#include <array>
#include <vector>
#include <string>
#include <span>

#include "rust/cxx.h"

// SHA-256 constants
static constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Right rotation function
constexpr uint32_t rotr(uint32_t x, char n)
{
	return ((x >> n) | (x << (32 - n)));
}

// SHA-256 logical functions
constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (~x & z));
}

constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}


std::vector<uint8_t> pad_message(const std::span<const uint8_t> &message)
{
	const size_t size = message.size();
	const size_t bit_len = size * 8;                     // Convert length to bits
    size_t padded_length = ((size + 9 + 63) / 64) * 64;  // Round up to nearest multiple of 512 bits (64 bytes)

	std::vector<uint8_t> pad_message(padded_length);
	std::copy(message.begin(), message.end(), pad_message.begin());
	pad_message[size] = 0x80;                                     // Append '1' bit

    for (size_t i = 0; i < 8; ++i) {
        pad_message[padded_length - 1 - i] = (bit_len >> (8 * i)) & 0xFF;  // Append bit length
	}

	return pad_message;
}

// SHA-256 computation
std::array<uint8_t, 32> sha256(const std::span<const uint8_t> &message) {

    std::vector<uint8_t> padded_message = pad_message(message);

	std::array<uint32_t, 8> H = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

    for (uint64_t chunk = 0; chunk < padded_message.size(); chunk += 64) {

        uint32_t W[64];

        for (int i = 0; i < 16; i++) {
			uint8_t* tmp = reinterpret_cast<uint8_t *>(&W[i]);

			tmp[0] = padded_message[chunk + 4 * i + 3];
			tmp[1] = padded_message[chunk + 4 * i + 2];
			tmp[2] = padded_message[chunk + 4 * i + 1];
			tmp[3] = padded_message[chunk + 4 * i];
        }

        for (int i = 16; i < 64; i++) {
			const uint32_t sigma0 = (rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3));
			const uint32_t sigma1 = (rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10));

            W[i] = (sigma1 + W[i - 7] + sigma0 + W[i - 16]) & 0xFFFFFFFF;
		}

		std::array<uint32_t, 8> H2(H);

        for (int i = 0; i < 64; i++) {
			const uint32_t sigma0 = (rotr(H2[0], 2) ^ rotr(H2[0], 13) ^ rotr(H2[0], 22));
			const uint32_t sigma1 = (rotr(H2[4], 6) ^ rotr(H2[4], 11) ^ rotr(H2[4], 25));

            const uint32_t T1 = (H2[7] + sigma1 + ch(H2[4], H2[5], H2[6]) + K[i] + W[i]) & 0xFFFFFFFF;
            const uint32_t T2 = (sigma0 + maj(H2[0], H2[1], H2[2])) & 0xFFFFFFFF;

			H2[7] = H2[6];
			H2[6] = H2[5];
			H2[5] = H2[4];
			H2[4] = (H2[3] + T1) & 0xFFFFFFFF;
			H2[3] = H2[2];
			H2[2] = H2[1];
			H2[1] = H2[0];
            H2[0] = (T1 + T2) & 0xFFFFFFFF;
        }

		for (int i = 0; i < 8; ++i)
			H[i] = (H[i] + H2[i]) & 0xFFFFFFFF;
    }

	std::array<uint8_t, 32> hash;

    for (int i = 0; i < 8; i++) {
		const uint8_t* tmp = reinterpret_cast<const uint8_t *>(&H[i]);

        hash[4 * i] = tmp[3];
        hash[4 * i + 1] = tmp[2];
        hash[4 * i + 2] = tmp[1];
        hash[4 * i + 3] = tmp[0];
    }

	return hash;
}

// Wrapper for Rust that uses rust::Slice
std::array<uint8_t, 32> sha256_wrapper(rust::Slice<const uint8_t> message) {
    // Convert rust::Slice to std::span
    std::span<const uint8_t> span{message.data(), message.size()};
    return sha256(span);
}
