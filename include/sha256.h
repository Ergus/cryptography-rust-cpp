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

std::array<uint8_t, 32> sha256_wrapper(rust::Slice<const uint8_t> message);

/* // Example usage */
/* int main() { */
/*     std::string message = "hello world"; */

/*     std::array<uint8_t, 32> hash = sha256(message); */

/*     printf("SHA-256: "); */
/*     for (int i = 0; i < 32; i++) { */
/*         printf("%02x", hash[i]); */
/*     } */
/*     printf("\n"); */

/*     return 0; */
/* } */
