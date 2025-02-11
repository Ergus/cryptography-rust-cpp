#pragma once

#include <array>
#include <span>
#include <cstdint>
#include <vector>

#include "rust/cxx.h"

// Padding and preprocessing
std::vector<uint8_t> pad_message(const std::span<const uint8_t> &message);

// SHA-256 computation
std::array<uint8_t, 32> sha256(const std::span<const uint8_t> &message);

inline std::string sha256(const std::string& message)
{
	constexpr char hexChars[] = "0123456789abcdef";

	std::array<uint8_t, 32> hash = sha256(std::span((uint8_t *)message.data(), message.size()));

	std::string hexStr;
	hexStr.reserve(2 * hash.size());

	for (uint8_t c : hash) {
		hexStr.push_back(hexChars[(c >> 4) & 0x0F]);
		hexStr.push_back(hexChars[c & 0x0F]);
	}
	return hexStr;
}

// Wrapper for Rust that uses rust::Slice
inline std::array<uint8_t, 32> sha256_wrapper_raw(rust::Slice<const uint8_t> message)
{
	// Convert rust::Slice to std::span
	std::span<const uint8_t> span{message.data(), message.size()};
	return sha256(span);
}

// Wrapper for Rust that uses rust::Slice
inline rust::String sha256_wrapper_str(const rust::Str message)
{
	// Convert rust::String to std::string
	return sha256(static_cast<std::string>(message));
}

