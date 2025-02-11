#include "sha256.h"
#include "keys.h"

// XOR Encryption using shared secret
std::vector<char> xorEncrypt(
	const std::string& message,
	const mpz_class& sharedSecret
) {
    std::string secretStr = sharedSecret.get_str(16); // Convert to string
    std::vector<char> encryptedMessage(message.size());

    for (size_t i = 0; i < message.size(); ++i)
        encryptedMessage[i] = message[i] ^ secretStr[i % secretStr.size()];

    return encryptedMessage;
}

// ECIES Encryption
std::pair<std::pair<mpz_class, mpz_class>, std::vector<char>> encryptMessage(
    const EllipticCurve& curve,
    const std::pair<mpz_class, mpz_class>& recipientPublicKey,
    const std::string& message
) {
    mpz_class ephemeralPrivateKey = curve.generatePrivateKey();
    std::pair<mpz_class, mpz_class> ephemeralPublicKey = curve.scalarMult(ephemeralPrivateKey);

    // Compute shared secret: S = ephemeralPrivateKey * recipientPublicKey
    std::pair<mpz_class, mpz_class> sharedPoint = curve.scalarMult(ephemeralPrivateKey, recipientPublicKey);

    // Use x-coordinate of shared point as the shared secret
    mpz_class sharedSecret = sharedPoint.first;

    // Encrypt the message with the shared secret using XOR
    std::vector<char> encryptedMessage = xorEncrypt(message, sharedSecret);

    return {ephemeralPublicKey, encryptedMessage};
}

// XOR Decryption using shared secret
std::string xorDecrypt(const std::vector<char>& encryptedMessage, const mpz_class& sharedSecret
) {
    std::string secretStr = sharedSecret.get_str(16); // Convert to string
    std::string decryptedMessage(encryptedMessage.size(), '\0');

    for (size_t i = 0; i < encryptedMessage.size(); ++i) {
        decryptedMessage[i] = encryptedMessage[i] ^ secretStr[i % secretStr.size()];
    }
    return decryptedMessage;
}

// ECIES Decryption
std::string decryptMessage(
    const EllipticCurve& curve,
    const mpz_class& recipientPrivateKey,
    const std::pair<std::pair<mpz_class, mpz_class>, std::vector<char>>& encryptedData
) {
    // Extract ephemeral public key and encrypted message
    const auto& ephemeralPublicKey = encryptedData.first;
    const auto& encryptedMessage = encryptedData.second;

    // Compute shared secret: S = recipientPrivateKey * ephemeralPublicKey
    std::pair<mpz_class, mpz_class> sharedPoint = curve.scalarMult(recipientPrivateKey, ephemeralPublicKey);

    // Use x-coordinate of shared point as the shared secret
    mpz_class sharedSecret = sharedPoint.first;

    // Decrypt the message with the shared secret using XOR
    return xorDecrypt(encryptedMessage, sharedSecret);
}
